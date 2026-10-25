package platform

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

//go:embed schema.sql
var schema embed.FS

type Store struct {
	DB  *pgxpool.Pool
	Key ed25519.PrivateKey
}

func Open(ctx context.Context, c Config) (*Store, error) {
	key, e := SigningKey(c.SigningSeed)
	if e != nil {
		return nil, e
	}
	db, e := pgxpool.New(ctx, c.DatabaseURL)
	if e != nil {
		return nil, e
	}
	s := &Store{db, key}
	if e = db.Ping(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(80267101)"); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT to_regclass('schema_versions') IS NOT NULL").Scan(&exists); e != nil {
		return e
	}
	if exists {
		var v int
		if e = tx.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM schema_versions").Scan(&v); e != nil {
			return e
		}
		if v > 1 {
			return errors.New("数据库迁移版本高于此程序，拒绝不兼容降级")
		}
	}
	b, _ := schema.ReadFile("schema.sql")
	if _, e = tx.Exec(ctx, string(b)); e != nil {
		return e
	}
	// Additive and reversible at the binary level: the previous release ignores this column.
	// Keep schema_versions at 1 so an emergency binary rollback remains bootable.
	if _, e = tx.Exec(ctx, "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS tls_public_ca boolean NOT NULL DEFAULT false"); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func audit(ctx context.Context, tx pgx.Tx, actor, action, target string, detail any) error {
	b, e := json.Marshal(detail)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO audit(actor,action,target,detail) VALUES($1,$2,$3,$4)", actor, action, target, b)
	return e
}
func (s *Store) Bootstrap(ctx context.Context, email, password string) (string, error) {
	if len(password) < 12 {
		return "", Bad("管理员密码至少 12 字符")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	if e != nil {
		return "", e
	}
	secret := Random()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(80267102)"); e != nil {
		return "", e
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM users WHERE role='super'").Scan(&n); e != nil {
		return "", e
	}
	if n > 0 {
		return "", Bad("已有超级管理员，拒绝再次初始化")
	}
	id := Random()
	_, e = tx.Exec(ctx, "INSERT INTO users(id,email,password,role,totp) VALUES($1,$2,$3,'super',$4)", id, email, h, secret)
	if e != nil {
		return "", e
	}
	if e = audit(ctx, tx, id, "bootstrap", id, map[string]string{"email": email}); e != nil {
		return "", e
	}
	return secret, tx.Commit(ctx)
}

type Redemption struct {
	ID       string     `json:"id"`
	BatchID  string     `json:"batch_id"`
	Before   *time.Time `json:"before_at"`
	After    time.Time  `json:"after_at"`
	Repeated bool       `json:"repeated"`
}

func (s *Store) Redeem(ctx context.Context, user, code, request string) (Redemption, error) {
	var out Redemption
	if len(request) < 8 || len(request) > 128 {
		return out, Bad("request_id 长度必须为 8–128")
	}
	code = Normalize(code)
	if len(code) != 32 {
		return out, Bad("充值码格式无效")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	// Every entitlement mutation locks the user first. This serializes same-user renewals and adjustments.
	var disabled bool
	if e = tx.QueryRow(ctx, "SELECT disabled FROM users WHERE id=$1 FOR UPDATE", user).Scan(&disabled); e != nil {
		return out, e
	}
	if disabled {
		return out, Deny("账号已禁用")
	}
	hash := Digest(code)
	var storedHash string
	e = tx.QueryRow(ctx, "SELECT id,batch_id,before_at,after_at,card_hash FROM redemptions WHERE user_id=$1 AND request_id=$2", user, request).Scan(&out.ID, &out.BatchID, &out.Before, &out.After, &storedHash)
	if e == nil {
		if storedHash != hash {
			return out, Bad("request_id 已用于另一张卡")
		}
		out.Repeated = true
		return out, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	var batch, plan string
	var seconds int64
	var deadline time.Time
	var off bool
	e = tx.QueryRow(ctx, "SELECT c.batch_id,c.disabled,b.plan_id,b.seconds,b.deadline FROM cards c JOIN batches b ON b.id=c.batch_id WHERE c.hash=$1 FOR UPDATE OF c", hash).Scan(&batch, &off, &plan, &seconds, &deadline)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, Bad("充值码不存在或不可用")
	}
	if e != nil {
		return out, e
	}
	var owner string
	e = tx.QueryRow(ctx, "SELECT id,user_id,batch_id,before_at,after_at FROM redemptions WHERE card_hash=$1", hash).Scan(&out.ID, &owner, &out.BatchID, &out.Before, &out.After)
	if e == nil {
		if owner != user {
			return out, Bad("充值码已使用")
		}
		out.Repeated = true
		return out, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return out, e
	}
	if off || !deadline.After(now) {
		return out, Bad("充值码已禁用或超过兑换截止时间")
	}
	var oldPlan string
	var before time.Time
	e = tx.QueryRow(ctx, "SELECT plan_id,expires_at FROM entitlements WHERE user_id=$1", user).Scan(&oldPlan, &before)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if oldPlan != "" && oldPlan != plan {
		return out, Bad("第一阶段仅允许同套餐续费，请联系管理员迁移套餐")
	}
	out = Redemption{ID: Random(), BatchID: batch, After: NextExpiry(before, now, seconds)}
	if !before.IsZero() {
		out.Before = &before
	}
	_, e = tx.Exec(ctx, "INSERT INTO entitlements(user_id,plan_id,expires_at) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET expires_at=excluded.expires_at", user, plan, out.After)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO redemptions(id,card_hash,user_id,batch_id,request_id,before_at,after_at) VALUES($1,$2,$3,$4,$5,$6,$7)", out.ID, hash, user, batch, request, out.Before, out.After)
	if e != nil {
		return out, e
	}
	if e = audit(ctx, tx, user, "redeem", out.ID, map[string]any{"batch": batch, "request_id": request, "before": out.Before, "after": out.After}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

type Rights struct {
	Plan      string
	Node      string
	Devices   int
	Tunnels   int
	Bandwidth int
	Expires   time.Time
}

func rights(ctx context.Context, tx pgx.Tx, user string) (Rights, error) {
	var r Rights
	var disabled bool
	if e := tx.QueryRow(ctx, "SELECT disabled FROM users WHERE id=$1 FOR UPDATE", user).Scan(&disabled); e != nil {
		return r, e
	}
	if disabled {
		return r, Deny("账号已禁用")
	}
	e := tx.QueryRow(ctx, `SELECT p.id,p.node_id,p.max_devices,p.max_tunnels,p.tunnel_kibps,e.expires_at FROM entitlements e JOIN plans p ON p.id=e.plan_id JOIN nodes n ON n.id=p.node_id WHERE e.user_id=$1 AND e.expires_at>clock_timestamp() AND n.enabled`, user).Scan(&r.Plan, &r.Node, &r.Devices, &r.Tunnels, &r.Bandwidth, &r.Expires)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, Deny("套餐未激活、已到期或节点维护中")
	}
	return r, e
}
func (s *Store) Bind(ctx context.Context, code string) (map[string]string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var user, name string
	// Read owner first, then lock user before binding row to preserve the global lock order.
	hash := Digest(Normalize(code))
	e = tx.QueryRow(ctx, "SELECT user_id FROM bind_codes WHERE hash=$1", hash).Scan(&user)
	if e != nil {
		return nil, Bad("绑定码无效")
	}
	r, e := rights(ctx, tx, user)
	if e != nil {
		return nil, e
	}
	e = tx.QueryRow(ctx, "SELECT name FROM bind_codes WHERE hash=$1 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE", hash).Scan(&name)
	if e != nil {
		return nil, Bad("绑定码已使用或过期")
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE user_id=$1 AND NOT revoked", user).Scan(&n); e != nil {
		return nil, e
	}
	if n >= r.Devices {
		return nil, Bad("设备数量达到套餐上限，请先撤销旧设备")
	}
	// Node row lock serializes port allocation across users and devices.
	var start, end int
	if e = tx.QueryRow(ctx, "SELECT control_start,control_end FROM nodes WHERE id=$1 FOR UPDATE", r.Node).Scan(&start, &end); e != nil {
		return nil, e
	}
	var port int
	e = tx.QueryRow(ctx, "SELECT p FROM generate_series($2::int,$3::int) p WHERE NOT EXISTS(SELECT 1 FROM devices WHERE node_id=$1 AND control_port=p) ORDER BY p LIMIT 1", r.Node, start, end).Scan(&port)
	if e != nil {
		return nil, Bad("节点控制端口池已满")
	}
	id, token := Random(), Random()
	_, e = tx.Exec(ctx, "INSERT INTO devices(id,user_id,node_id,name,token_hash,control_port) VALUES($1,$2,$3,$4,$5,$6)", id, user, r.Node, name, Digest(token), port)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "UPDATE bind_codes SET used=true WHERE hash=$1", hash); e != nil {
		return nil, e
	}
	if e = audit(ctx, tx, user, "bind", id, map[string]any{}); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return map[string]string{"device_id": id, "credential": token}, nil
}
func (s *Store) CreateTunnel(ctx context.Context, user string, t Tunnel) (Tunnel, error) {
	if len(t.Name) < 1 || len(t.Name) > 80 || len(t.LocalHost) < 1 || len(t.LocalHost) > 253 || t.LocalPort < 1 || t.LocalPort > 65535 || (t.Protocol != "tcp" && t.Protocol != "udp") {
		return t, Bad("请检查名称、本地地址、端口和 TCP/UDP 协议")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return t, e
	}
	defer tx.Rollback(ctx)
	r, e := rights(ctx, tx, user)
	if e != nil {
		return t, e
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM tunnels WHERE user_id=$1", user).Scan(&n); e != nil {
		return t, e
	}
	if n >= r.Tunnels {
		return t, Bad("隧道数量达到套餐上限")
	}
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE id=$1 AND user_id=$2 AND node_id=$3 AND NOT revoked", t.DeviceID, user, r.Node).Scan(&n); e != nil {
		return t, e
	}
	if n != 1 {
		return t, Deny("设备不可用或不属于当前账号")
	}
	var start, end int
	if e = tx.QueryRow(ctx, "SELECT port_start,port_end FROM nodes WHERE id=$1 FOR UPDATE", r.Node).Scan(&start, &end); e != nil {
		return t, e
	}
	if t.RemotePort != 0 && (t.RemotePort < start || t.RemotePort > end) {
		return t, Bad("远程端口不在套餐节点的端口池内")
	}
	if t.RemotePort == 0 {
		e = tx.QueryRow(ctx, "SELECT p FROM generate_series($2::int,$3::int) p WHERE NOT EXISTS(SELECT 1 FROM tunnels WHERE node_id=$1 AND remote_port=p) ORDER BY p LIMIT 1", r.Node, start, end).Scan(&t.RemotePort)
		if e != nil {
			return t, Bad("端口池已满")
		}
	}
	t.ID = Random()
	_, e = tx.Exec(ctx, "INSERT INTO tunnels(id,user_id,device_id,node_id,name,protocol,local_host,local_port,remote_port) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", t.ID, user, t.DeviceID, r.Node, t.Name, t.Protocol, t.LocalHost, t.LocalPort, t.RemotePort)
	if e != nil {
		return t, Bad("端口已被占用，请选择其他端口或自动分配")
	}
	if e = audit(ctx, tx, user, "tunnel.create", t.ID, t); e != nil {
		return t, e
	}
	return t, tx.Commit(ctx)
}
func (s *Store) Grants(ctx context.Context, node string) ([]Grant, error) {
	rows, e := s.DB.Query(ctx, `SELECT d.id,d.control_port,d.generation,e.expires_at,p.tunnel_kibps FROM devices d JOIN users u ON u.id=d.user_id JOIN entitlements e ON e.user_id=u.id JOIN plans p ON p.id=e.plan_id JOIN nodes n ON n.id=d.node_id WHERE d.node_id=$1 AND p.node_id=d.node_id AND NOT d.revoked AND NOT u.disabled AND n.enabled AND e.expires_at>clock_timestamp() ORDER BY d.id`, node)
	if e != nil {
		return nil, e
	}
	grants := []Grant{}
	for rows.Next() {
		var g Grant
		var generation int
		if e = rows.Scan(&g.DeviceID, &g.ControlPort, &generation, &g.ExpiresAt, &g.BandwidthKB); e != nil {
			rows.Close()
			return nil, e
		}
		g.Token = DeviceFRPToken(s.Key, g.DeviceID, generation)
		grants = append(grants, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range grants {
		g := &grants[i]
		g.Tunnels = []Tunnel{}
		r, e := s.DB.Query(ctx, "SELECT id,name,protocol,local_host,local_port,remote_port,device_id FROM tunnels WHERE device_id=$1 AND NOT paused ORDER BY id", g.DeviceID)
		if e != nil {
			return nil, e
		}
		for r.Next() {
			var t Tunnel
			if e = r.Scan(&t.ID, &t.Name, &t.Protocol, &t.LocalHost, &t.LocalPort, &t.RemotePort, &t.DeviceID); e != nil {
				r.Close()
				return nil, e
			}
			g.Tunnels = append(g.Tunnels, t)
		}
		e = r.Err()
		r.Close()
		if e != nil {
			return nil, e
		}
	}
	return grants, nil
}
func (s *Store) String() string {
	return fmt.Sprintf("store(public-key=%x)", s.Key.Public().(ed25519.PublicKey)[:4])
}
