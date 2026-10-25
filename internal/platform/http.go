package platform

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type Principal struct {
	ID, Email, Role, TOTP string
	Password              []byte
}
type endpoint func(http.ResponseWriter, *http.Request, *Principal) error
type bucket struct {
	At    time.Time
	Count int
}
type API struct {
	S      *Store
	C      Config
	mux    *http.ServeMux
	mu     sync.Mutex
	limits map[string]bucket
	Assets fs.FS
}

func NewAPI(s *Store, c Config, assets fs.FS) *API {
	a := &API{S: s, C: c, mux: http.NewServeMux(), limits: make(map[string]bucket), Assets: assets}
	a.route("GET /healthz", false, false, a.health)
	a.route("POST /api/register", false, false, a.register)
	a.route("POST /api/login", false, false, a.login)
	a.route("POST /api/logout", true, false, a.logout)
	a.route("POST /api/sessions/revoke", true, false, a.revokeSessions)
	a.route("GET /api/me", true, false, a.me)
	a.route("POST /api/redeem", true, false, a.redeem)
	a.route("POST /api/bind-codes", true, false, a.bindCode)
	a.route("POST /api/device/bind", false, false, a.bind)
	a.route("GET /api/devices", true, false, a.devices)
	a.route("POST /api/devices/{id}/revoke", true, false, a.revokeDevice)
	a.route("GET /api/tunnels", true, false, a.tunnels)
	a.route("POST /api/tunnels", true, false, a.createTunnel)
	a.route("PATCH /api/tunnels/{id}", true, false, a.editTunnel)
	a.route("DELETE /api/tunnels/{id}", true, false, a.deleteTunnel)
	a.route("GET /api/redemptions", true, false, a.history)
	a.route("GET /api/device/config", false, false, a.deviceConfig)
	a.route("POST /api/node/lease", false, false, a.nodeLease)
	a.route("POST /api/node/setup", false, false, a.nodeSetup)
	a.route("POST /api/node/check", false, false, a.nodeCheck)
	a.route("GET /api/admin/overview", true, true, a.overview)
	a.route("POST /api/admin/nodes", true, true, a.createNode)
	a.route("POST /api/admin/nodes/{id}/state", true, true, a.nodeState)
	a.route("POST /api/admin/plans", true, true, a.createPlan)
	a.route("POST /api/admin/cards", true, true, a.cards)
	a.route("POST /api/admin/batches/{id}/disable", true, true, a.disableBatch)
	a.route("POST /api/admin/users/{id}/state", true, true, a.userState)
	a.route("POST /api/admin/users/{id}/adjust", true, true, a.adjust)
	a.route("GET /api/admin/audit", true, true, a.auditList)
	a.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			JSON(w, 404, map[string]string{"error": "接口不存在"})
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})
	return a
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if !a.C.DevHTTP {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	a.mux.ServeHTTP(w, r)
}
func (a *API) allow(key string, max int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.limits) > 5000 {
		for k, b := range a.limits {
			if now.Sub(b.At) > time.Minute {
				delete(a.limits, k)
			}
		}
		if len(a.limits) > 10000 {
			return false
		}
	}
	b := a.limits[key]
	if now.Sub(b.At) >= time.Minute {
		b = bucket{At: now}
	}
	b.Count++
	a.limits[key] = b
	return b.Count <= max
}
func (a *API) route(pattern string, auth, admin bool, f endpoint) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		max := 300
		if strings.Contains(pattern, "/api/node/check") {
			max = 6000
		}
		if strings.Contains(pattern, "login") || strings.Contains(pattern, "register") {
			max = 12
		}
		if !a.allow("ip:"+host+":"+pattern, max) {
			JSON(w, 429, map[string]string{"error": "请求过多，请一分钟后重试"})
			return
		}
		// No proxy headers are trusted for rate-limit identity. Reverse proxy deployments also limit at their edge.
		origin := r.Header.Get("Origin")
		if origin != "" && origin != strings.TrimRight(a.C.PublicURL, "/") {
			JSON(w, 403, map[string]string{"error": "来源校验失败"})
			return
		}
		var p *Principal
		var err error
		if auth {
			p, err = a.authenticate(r)
			if err == nil && r.Method != "GET" && r.Header.Get("Authorization") == "" && origin == "" {
				err = Deny("Cookie 写请求必须携带正确 Origin")
			}
		}
		if err == nil && admin {
			if p.Role != "super" && p.Role != "operator" {
				err = Deny("需要管理员权限")
			} else if r.Method != "GET" {
				if !CheckTOTP(p.TOTP, r.Header.Get("X-Admin-OTP")) || bcrypt.CompareHashAndPassword(p.Password, []byte(r.Header.Get("X-Admin-Password"))) != nil {
					err = Deny("敏感操作需要管理员密码及当前动态验证码")
				}
			}
		}
		if err == nil {
			err = f(w, r, p)
		}
		if err != nil {
			var e APIError
			if errors.As(err, &e) {
				JSON(w, e.Status, map[string]string{"error": e.Message})
			} else {
				slog.Error("api failure", "method", r.Method, "path", r.URL.Path, "error", err)
				JSON(w, 500, map[string]string{"error": "服务暂时异常，请稍后重试并联系管理员"})
			}
		}
	})
}
func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
func (a *API) authenticate(r *http.Request) (*Principal, error) {
	token := bearer(r)
	if token == "" {
		if c, e := r.Cookie("session"); e == nil {
			token = c.Value
		}
	}
	p := &Principal{}
	e := a.S.DB.QueryRow(r.Context(), "SELECT u.id,u.email,u.role,u.totp,u.password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=$1 AND s.expires_at>clock_timestamp() AND NOT u.disabled", Digest(token)).Scan(&p.ID, &p.Email, &p.Role, &p.TOTP, &p.Password)
	if e != nil {
		return nil, APIError{401, "请重新登录"}
	}
	return p, nil
}
func list(ctx context.Context, s *Store, q string, args ...any) ([]map[string]any, error) {
	rows, e := s.DB.Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		v, e := rows.Values()
		if e != nil {
			return nil, e
		}
		m := map[string]any{}
		for i, f := range rows.FieldDescriptions() {
			m[f.Name] = v[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (a *API) health(w http.ResponseWriter, r *http.Request, p *Principal) error {
	if e := a.S.DB.Ping(r.Context()); e != nil {
		return APIError{503, "数据库不可用"}
	}
	JSON(w, 200, map[string]string{"status": "ok", "version": Version})
	return nil
}
func (a *API) register(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	v.Email = strings.ToLower(strings.TrimSpace(v.Email))
	m, e := mail.ParseAddress(v.Email)
	if e != nil || m.Address != v.Email || len(v.Email) > 254 || len(v.Password) < 12 || len(v.Password) > 72 {
		return Bad("请输入有效邮箱和 12–72 字节密码")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(v.Password), 12)
	if e != nil {
		return e
	}
	id := Random()
	_, e = a.S.DB.Exec(r.Context(), "INSERT INTO users(id,email,password,role) VALUES($1,$2,$3,'user')", id, v.Email, h)
	if e != nil {
		return Bad("该邮箱无法注册，请尝试登录")
	}
	JSON(w, 201, map[string]string{"id": id})
	return nil
}
func (a *API) login(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if len(v.Password) > 72 {
		return Bad("密码过长")
	}
	var id, role, totp string
	var h []byte
	email := strings.ToLower(strings.TrimSpace(v.Email))
	if !a.allow("login:"+email, 8) {
		return APIError{429, "该账号尝试次数过多"}
	}
	e := a.S.DB.QueryRow(r.Context(), "SELECT id,password,role,totp FROM users WHERE email=$1 AND NOT disabled", email).Scan(&id, &h, &role, &totp)
	if e != nil || bcrypt.CompareHashAndPassword(h, []byte(v.Password)) != nil {
		return APIError{401, "邮箱或密码错误"}
	}
	if role != "user" && !CheckTOTP(totp, v.OTP) {
		return APIError{401, "管理员需要正确的双因素动态验证码"}
	}
	token := Random()
	_, e = a.S.DB.Exec(r.Context(), "INSERT INTO sessions(hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '12 hours')", Digest(token), id)
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, Secure: !a.C.DevHTTP, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	JSON(w, 200, map[string]string{"token": token, "role": role})
	return nil
}
func (a *API) logout(w http.ResponseWriter, r *http.Request, p *Principal) error {
	token := bearer(r)
	if token == "" {
		c, _ := r.Cookie("session")
		if c != nil {
			token = c.Value
		}
	}
	_, e := a.S.DB.Exec(r.Context(), "DELETE FROM sessions WHERE hash=$1", Digest(token))
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Path: "/", HttpOnly: true, Secure: !a.C.DevHTTP, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	JSON(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *API) revokeSessions(w http.ResponseWriter, r *http.Request, p *Principal) error {
	_, e := a.S.DB.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=$1", p.ID)
	if e != nil {
		return e
	}
	JSON(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *API) me(w http.ResponseWriter, r *http.Request, p *Principal) error {
	ent, e := list(r.Context(), a.S, `SELECT p.id AS plan_id,p.name,p.max_devices,p.max_tunnels,p.tunnel_kibps,e.expires_at,n.host,n.name AS node_name,n.last_seen,clock_timestamp() AS server_now FROM entitlements e JOIN plans p ON p.id=e.plan_id JOIN nodes n ON n.id=p.node_id WHERE e.user_id=$1`, p.ID)
	if e != nil {
		return e
	}
	JSON(w, 200, map[string]any{"id": p.ID, "email": p.Email, "role": p.Role, "entitlements": ent, "server_now": time.Now().UTC()})
	return nil
}
func (a *API) redeem(w http.ResponseWriter, r *http.Request, p *Principal) error {
	if !a.allow("redeem:"+p.ID, 10) {
		return APIError{429, "兑换尝试过多，请稍后重试"}
	}
	var v struct {
		Code    string `json:"code"`
		Request string `json:"request_id"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	out, e := a.S.Redeem(r.Context(), p.ID, v.Code, v.Request)
	if e != nil {
		return e
	}
	JSON(w, 200, out)
	return nil
}
func (a *API) bindCode(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Name string `json:"name"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if v.Name == "" || len(v.Name) > 80 {
		return Bad("设备名称需为 1–80 字节")
	}
	code := Random()
	_, e := a.S.DB.Exec(r.Context(), "INSERT INTO bind_codes(hash,user_id,name,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '5 minutes')", Digest(code), p.ID, v.Name)
	if e != nil {
		return e
	}
	JSON(w, 201, map[string]any{"code": Group(code), "expires_seconds": 300})
	return nil
}
func (a *API) bind(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Code string `json:"code"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	out, e := a.S.Bind(r.Context(), v.Code)
	if e != nil {
		return e
	}
	JSON(w, 201, out)
	return nil
}
func (a *API) devices(w http.ResponseWriter, r *http.Request, p *Principal) error {
	o, e := list(r.Context(), a.S, "SELECT d.id,d.name,d.node_id,d.control_port,d.revoked,d.created_at,n.last_seen AS node_last_seen FROM devices d JOIN nodes n ON n.id=d.node_id WHERE user_id=$1 ORDER BY created_at", p.ID)
	if e != nil {
		return e
	}
	JSON(w, 200, o)
	return nil
}
func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request, p *Principal) error {
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "UPDATE devices SET revoked=true,generation=generation+1 WHERE id=$1 AND user_id=$2 AND NOT revoked", r.PathValue("id"), p.ID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return APIError{404, "设备不存在或已撤销"}
	}
	if e = audit(r.Context(), tx, p.ID, "device.revoke", r.PathValue("id"), map[string]any{}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 200, map[string]int{"maximum_revoke_seconds": LeaseSeconds + 1})
	return nil
}
func (a *API) tunnels(w http.ResponseWriter, r *http.Request, p *Principal) error {
	o, e := list(r.Context(), a.S, "SELECT t.*,n.host AS node_host FROM tunnels t JOIN nodes n ON n.id=t.node_id WHERE user_id=$1 ORDER BY id", p.ID)
	if e != nil {
		return e
	}
	JSON(w, 200, o)
	return nil
}
func (a *API) createTunnel(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var t Tunnel
	if e := decode(r, &t); e != nil {
		return e
	}
	t, e := a.S.CreateTunnel(r.Context(), p.ID, t)
	if e != nil {
		return e
	}
	JSON(w, 201, t)
	return nil
}
func (a *API) editTunnel(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Name      string `json:"name"`
		LocalHost string `json:"local_host"`
		LocalPort int    `json:"local_port"`
		Paused    bool   `json:"paused"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if v.Name == "" || len(v.Name) > 80 || v.LocalHost == "" || len(v.LocalHost) > 253 || v.LocalPort < 1 || v.LocalPort > 65535 {
		return Bad("名称、本地地址和端口无效")
	}
	return a.mutateOwned(w, r, p, "tunnel.update", "UPDATE tunnels SET name=$3,local_host=$4,local_port=$5,paused=$6 WHERE id=$1 AND user_id=$2", v.Name, v.LocalHost, v.LocalPort, v.Paused)
}
func (a *API) deleteTunnel(w http.ResponseWriter, r *http.Request, p *Principal) error {
	return a.mutateOwned(w, r, p, "tunnel.delete", "DELETE FROM tunnels WHERE id=$1 AND user_id=$2")
}
func (a *API) mutateOwned(w http.ResponseWriter, r *http.Request, p *Principal, action, q string, args ...any) error {
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	v := append([]any{r.PathValue("id"), p.ID}, args...)
	tag, e := tx.Exec(r.Context(), q, v...)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return APIError{404, "记录不存在"}
	}
	if e = audit(r.Context(), tx, p.ID, action, r.PathValue("id"), map[string]any{"values": args}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 200, map[string]string{"state": "saved", "message": "配置已保存；节点和客户端通常在 5 秒内获取，已有连接可能中断"})
	return nil
}
func (a *API) history(w http.ResponseWriter, r *http.Request, p *Principal) error {
	o, e := list(r.Context(), a.S, "SELECT r.id,b.name,r.before_at,r.after_at,r.created_at FROM redemptions r JOIN batches b ON b.id=r.batch_id WHERE user_id=$1 ORDER BY r.created_at DESC LIMIT 200", p.ID)
	if e != nil {
		return e
	}
	JSON(w, 200, o)
	return nil
}
func (a *API) nodeCheck(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		NodeID   string `json:"node_id"`
		DeviceID string `json:"device_id"`
		Op       string `json:"op"`
		Proxy    string `json:"proxy"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	var hash string
	e := a.S.DB.QueryRow(r.Context(), "SELECT token_hash FROM nodes WHERE id=$1", v.NodeID).Scan(&hash)
	if e != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(Digest(bearer(r)))) != 1 {
		return APIError{401, "节点身份无效"}
	}
	switch v.Op {
	case "Login", "NewProxy", "NewUserConn", "NewWorkConn":
	default:
		return Deny("操作无效")
	}
	var ok bool
	e = a.S.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id JOIN entitlements e ON e.user_id=u.id JOIN plans p ON p.id=e.plan_id JOIN nodes n ON n.id=d.node_id WHERE d.id=$1 AND d.node_id=$2 AND p.node_id=d.node_id AND NOT d.revoked AND NOT u.disabled AND n.enabled AND e.expires_at>clock_timestamp())`, v.DeviceID, v.NodeID).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return Deny("设备权益无效")
	}
	if v.Op == "NewProxy" || v.Op == "NewUserConn" {
		e = a.S.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM tunnels WHERE id=$1 AND device_id=$2 AND NOT paused)", v.Proxy, v.DeviceID).Scan(&ok)
		if e != nil {
			return e
		}
		if !ok {
			return Deny("隧道未授权")
		}
	}
	JSON(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *API) nodeLease(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		NodeID string `json:"node_id"`
		Nonce  string `json:"nonce"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if len(v.Nonce) != 32 {
		return Bad("nonce 无效")
	}
	var h string
	e := a.S.DB.QueryRow(r.Context(), "SELECT token_hash FROM nodes WHERE id=$1", v.NodeID).Scan(&h)
	if e != nil || subtle.ConstantTimeCompare([]byte(h), []byte(Digest(bearer(r)))) != 1 {
		return APIError{401, "节点身份无效"}
	}
	grants, e := a.S.Grants(r.Context(), v.NodeID)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	out := SignLease(a.S.Key, Lease{Version: 1, NodeID: v.NodeID, Nonce: v.Nonce, IssuedAt: now, Until: now.Add(LeaseSeconds * time.Second), Grants: grants})
	if _, e = a.S.DB.Exec(r.Context(), "UPDATE nodes SET last_seen=clock_timestamp() WHERE id=$1", v.NodeID); e != nil {
		return e
	}
	JSON(w, 200, out)
	return nil
}
func (a *API) nodeSetup(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		NodeID string `json:"node_id"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	var host, hash string
	var publicCA, enabled bool
	e := a.S.DB.QueryRow(r.Context(), "SELECT host,token_hash,tls_public_ca,enabled FROM nodes WHERE id=$1", v.NodeID).Scan(&host, &hash, &publicCA, &enabled)
	if e != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(Digest(bearer(r)))) != 1 {
		return APIError{401, "节点身份无效"}
	}
	if !enabled || !publicCA {
		return Bad("节点尚未启用一键公网证书模式，请从控制台重新创建节点")
	}
	JSON(w, 200, map[string]any{"host": host, "tls_public_ca": publicCA, "verify_key": a.S.Key.Public().(ed25519.PublicKey)})
	return nil
}
func (a *API) deviceConfig(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var id, node, host string
	var publicCA bool
	e := a.S.DB.QueryRow(r.Context(), "SELECT d.id,d.node_id,n.host,n.tls_public_ca FROM devices d JOIN nodes n ON n.id=d.node_id WHERE d.token_hash=$1 AND NOT d.revoked", Digest(bearer(r))).Scan(&id, &node, &host, &publicCA)
	if e != nil {
		return APIError{401, "设备凭据失效，请重新绑定"}
	}
	grants, e := a.S.Grants(r.Context(), node)
	if e != nil {
		return e
	}
	for _, g := range grants {
		if g.DeviceID == id {
			JSON(w, 200, map[string]any{"version": 1, "host": host, "grant": g, "public_ca": publicCA, "config_version": Digest(ClientConfig(g, host, "CA_FILE")), "state": "saved"})
			return nil
		}
	}
	return Deny("套餐到期、账号禁用或节点维护中，请检查用户中心")
}
func (a *API) overview(w http.ResponseWriter, r *http.Request, p *Principal) error {
	out := map[string]any{}
	queries := map[string]string{
		"nodes":   "SELECT id,name,host,control_start,control_end,port_start,port_end,tls_public_ca,enabled,last_seen FROM nodes ORDER BY id",
		"plans":   "SELECT * FROM plans ORDER BY created_at DESC",
		"batches": "SELECT b.*,count(c.hash) AS card_count,count(r.id) AS redeemed_count,count(*) FILTER(WHERE c.disabled) AS disabled_count FROM batches b JOIN cards c ON c.batch_id=b.id LEFT JOIN redemptions r ON r.card_hash=c.hash GROUP BY b.id ORDER BY b.created_at DESC LIMIT 200",
		"users":   "SELECT u.id,u.email,u.role,u.disabled,p.name AS plan_name,e.expires_at FROM users u LEFT JOIN entitlements e ON e.user_id=u.id LEFT JOIN plans p ON p.id=e.plan_id ORDER BY u.created_at DESC LIMIT 500",
	}
	for k, q := range queries {
		v, e := list(r.Context(), a.S, q)
		if e != nil {
			return e
		}
		out[k] = v
	}
	JSON(w, 200, out)
	return nil
}
func (a *API) createNode(w http.ResponseWriter, r *http.Request, p *Principal) error {
	if p.Role != "super" {
		return Deny("仅超级管理员可创建节点")
	}
	var v struct {
		Name         string `json:"name"`
		Host         string `json:"host"`
		ControlStart int    `json:"control_start"`
		ControlEnd   int    `json:"control_end"`
		PortStart    int    `json:"port_start"`
		PortEnd      int    `json:"port_end"`
		PublicCA     bool   `json:"tls_public_ca"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	v.Host = strings.ToLower(v.Host)
	if v.Name == "" || len(v.Name) > 80 || !validHost(v.Host) || (v.PublicCA && (net.ParseIP(v.Host) != nil || v.Host == "localhost")) || v.ControlStart < 1024 || v.ControlEnd > 65535 || v.ControlEnd < v.ControlStart || v.PortStart < 1024 || v.PortEnd > 65535 || v.PortEnd < v.PortStart || !(v.ControlEnd < v.PortStart || v.PortEnd < v.ControlStart) {
		return Bad("节点主机名、端口池或控制端口范围无效；两个范围不能重叠")
	}
	id, token := Random(), Random()
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	_, e = tx.Exec(r.Context(), "INSERT INTO nodes(id,name,host,token_hash,control_start,control_end,port_start,port_end,tls_public_ca) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, v.Name, v.Host, Digest(token), v.ControlStart, v.ControlEnd, v.PortStart, v.PortEnd, v.PublicCA)
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, p.ID, "node.create", id, v); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 201, map[string]any{"node_id": id, "credential": token, "verify_key": a.S.Key.Public().(ed25519.PublicKey)})
	return nil
}
func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "localhost" {
		return true
	}
	if len(strings.Split(h, ".")) < 2 {
		return false
	}
	label := regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	for _, part := range strings.Split(h, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}
func (a *API) nodeState(w http.ResponseWriter, r *http.Request, p *Principal) error {
	if p.Role != "super" {
		return Deny("仅超级管理员可变更节点状态")
	}
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	return a.adminMutation(w, r, p, "node.state", "UPDATE nodes SET enabled=$2 WHERE id=$1", v.Enabled)
}
func (a *API) createPlan(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Name       string `json:"name"`
		NodeID     string `json:"node_id"`
		MaxDevices int    `json:"max_devices"`
		MaxTunnels int    `json:"max_tunnels"`
		TunnelKB   int    `json:"tunnel_kibps"`
		Price      int64  `json:"price_cents"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if v.Name == "" || len(v.Name) > 80 || v.MaxDevices < 1 || v.MaxDevices > 16 || v.MaxTunnels < 1 || v.MaxTunnels > 128 || v.TunnelKB < 1 || v.TunnelKB > 1048576 || v.Price < 0 {
		return Bad("套餐参数无效；带宽单位为 KiB/s")
	}
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	id := Random()
	_, e = tx.Exec(r.Context(), "INSERT INTO plans(id,name,node_id,max_devices,max_tunnels,tunnel_kibps,price_cents) VALUES($1,$2,$3,$4,$5,$6,$7)", id, v.Name, v.NodeID, v.MaxDevices, v.MaxTunnels, v.TunnelKB, v.Price)
	if e != nil {
		return Bad("节点不存在或套餐参数错误")
	}
	if e = audit(r.Context(), tx, p.ID, "plan.create", id, v); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 201, map[string]string{"id": id})
	return nil
}
func (a *API) cards(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Name     string    `json:"name"`
		Note     string    `json:"note"`
		PlanID   string    `json:"plan_id"`
		Seconds  int64     `json:"seconds"`
		Count    int       `json:"count"`
		Deadline time.Time `json:"deadline"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if v.Name == "" || len(v.Name) > 80 || len(v.Note) > 1000 || v.Count < 1 || v.Count > 1000 || v.Seconds < 1 || v.Seconds > 315360000 || !v.Deadline.After(time.Now()) {
		return Bad("批次名称、数量（1–1000）、时长或兑换截止时间无效")
	}
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var active bool
	if e = tx.QueryRow(r.Context(), "SELECT active FROM plans WHERE id=$1", v.PlanID).Scan(&active); e != nil || !active {
		return Bad("套餐不可售")
	}
	id := Random()
	_, e = tx.Exec(r.Context(), "INSERT INTO batches(id,name,note,plan_id,seconds,deadline,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)", id, v.Name, v.Note, v.PlanID, v.Seconds, v.Deadline, p.ID)
	if e != nil {
		return e
	}
	codes := []string{}
	for i := 0; i < v.Count; i++ {
		code := Random()
		_, e = tx.Exec(r.Context(), "INSERT INTO cards(hash,batch_id) VALUES($1,$2)", Digest(code), id)
		if e != nil {
			return e
		}
		codes = append(codes, Group(code))
	}
	if e = audit(r.Context(), tx, p.ID, "cards.generate-and-export", id, v); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 201, map[string]any{"batch_id": id, "codes": codes, "warning": "明文仅返回一次；响应丢失时禁用本批次并重新生成"})
	return nil
}
func (a *API) adminMutation(w http.ResponseWriter, r *http.Request, p *Principal, action, q string, args ...any) error {
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	v := append([]any{r.PathValue("id")}, args...)
	tag, e := tx.Exec(r.Context(), q, v...)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return APIError{404, "目标不存在或无可变更记录"}
	}
	if e = audit(r.Context(), tx, p.ID, action, r.PathValue("id"), map[string]any{"values": args}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *API) disableBatch(w http.ResponseWriter, r *http.Request, p *Principal) error {
	return a.adminMutation(w, r, p, "batch.disable", "UPDATE cards SET disabled=true WHERE batch_id=$1 AND NOT EXISTS(SELECT 1 FROM redemptions r WHERE r.card_hash=cards.hash)")
}
func (a *API) userState(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Disabled bool `json:"disabled"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if r.PathValue("id") == p.ID {
		return Bad("不可禁用当前管理员")
	}
	return a.adminMutation(w, r, p, "user.state", "UPDATE users SET disabled=$2 WHERE id=$1 AND role='user'", v.Disabled)
}
func (a *API) adjust(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var v struct {
		Seconds int64  `json:"seconds"`
		Reason  string `json:"reason"`
	}
	if e := decode(r, &v); e != nil {
		return e
	}
	if v.Seconds < -315360000 || v.Seconds > 315360000 || v.Seconds == 0 || len(strings.TrimSpace(v.Reason)) < 4 || len(v.Reason) > 1000 {
		return Bad("请输入非零调整秒数及至少 4 字节的原因")
	}
	tx, e := a.S.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var id string
	var before time.Time
	if e = tx.QueryRow(r.Context(), "SELECT id FROM users WHERE id=$1 FOR UPDATE", r.PathValue("id")).Scan(&id); e != nil {
		return APIError{404, "用户不存在"}
	}
	if e = tx.QueryRow(r.Context(), "SELECT expires_at FROM entitlements WHERE user_id=$1", id).Scan(&before); e != nil {
		return Bad("该用户尚无套餐")
	}
	after := before.Add(time.Duration(v.Seconds) * time.Second)
	_, e = tx.Exec(r.Context(), "UPDATE entitlements SET expires_at=$2 WHERE user_id=$1", id, after)
	if e != nil {
		return e
	}
	adjustID := Random()
	_, e = tx.Exec(r.Context(), "INSERT INTO adjustments(id,user_id,actor,seconds,reason,before_at,after_at) VALUES($1,$2,$3,$4,$5,$6,$7)", adjustID, id, p.ID, v.Seconds, v.Reason, before, after)
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, p.ID, "entitlement.adjust", id, map[string]any{"id": adjustID, "before": before, "after": after, "reason": v.Reason}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	JSON(w, 200, map[string]any{"expires_at": after})
	return nil
}
func (a *API) auditList(w http.ResponseWriter, r *http.Request, p *Principal) error {
	o, e := list(r.Context(), a.S, "SELECT * FROM audit ORDER BY id DESC LIMIT 500")
	if e != nil {
		return e
	}
	JSON(w, 200, o)
	return nil
}

func Serve(ctx context.Context, c Config, assets fs.FS) error {
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Host == "" {
		return errors.New("public_url 必须是完整 URL")
	}
	if c.DevHTTP {
		host, _, e := net.SplitHostPort(c.Listen)
		if e != nil || !(host == "localhost" || net.ParseIP(host).IsLoopback()) {
			return errors.New("dev_http 仅允许回环监听")
		}
	} else if u.Scheme != "https" {
		return errors.New("生产 public_url 必须为 HTTPS")
	}
	if !c.DevHTTP && !c.ReverseProxyTLS && (c.TLSCert == "" || c.TLSKey == "") {
		return errors.New("必须配置 TLS 证书或明确 reverse_proxy_tls")
	}
	s, e := Open(ctx, c)
	if e != nil {
		return e
	}
	defer s.DB.Close()
	if e = s.Migrate(ctx); e != nil {
		return e
	}
	srv := &http.Server{Addr: c.Listen, Handler: NewAPI(s, c, assets), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("control listening", "address", c.Listen, "version", Version)
	if c.TLSCert != "" {
		e = srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	} else {
		e = srv.ListenAndServe()
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("control: %w", e)
}

var _ = pgx.ErrNoRows
