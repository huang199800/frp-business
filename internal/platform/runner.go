package platform

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func HTTPClient(c Config) (*http.Client, error) {
	u, e := url.Parse(c.ControlURL)
	if e != nil || u.Host == "" {
		return nil, errors.New("control_url 无效")
	}
	if u.Scheme != "https" {
		if !c.DevHTTP || !(u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()) {
			return nil, errors.New("控制 API 必须使用 HTTPS，开发模式仅允许回环 HTTP")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		b, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("CA 文件无有效证书")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func request(ctx context.Context, client *http.Client, c Config, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.ControlURL, "/")+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var v struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, v.Error)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}
func validateFRP(path, kind string) error {
	if path == "" {
		return errors.New("frp_path 未设置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, path, "--version").Output()
	if e != nil {
		return fmt.Errorf("无法执行 %s: %w", kind, e)
	}
	if strings.TrimSpace(string(b)) != FRPVersion {
		return fmt.Errorf("%s 版本需为 %s，实际为 %s", kind, FRPVersion, b)
	}
	return nil
}

// Atomic writes are consumed only after rename, never while partially written.
func atomicFile(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".new-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, path)
}

type child struct {
	cmd     *exec.Cmd
	done    chan error
	cleanup func()
}

func launch(ctx context.Context, path string, args ...string) (*child, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	prepareChild(cmd)
	cmd.Stdout = LogOutput
	cmd.Stderr = LogOutput
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	cleanup, e := containChild(cmd)
	if e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, e
	}
	ch := &child{cmd: cmd, done: make(chan error, 1), cleanup: cleanup}
	go func() { ch.done <- cmd.Wait() }()
	return ch, nil
}
func (c *child) stop() {
	if c == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	<-c.done
	c.cleanup()
}
func Node(ctx context.Context, c Config) error {
	if e := validateFRP(c.FRPPath, "frps"); e != nil {
		return e
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("节点必须配置 tls_cert 和 tls_key")
	}
	if _, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey); e != nil {
		return e
	}
	key, e := base64.StdEncoding.DecodeString(c.VerifyKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("verify_key 无效")
	}
	client, e := HTTPClient(c)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	configFile := filepath.Join(c.StateDir, "node-runtime.json")
	if e = SaveConfig(configFile, c); e != nil {
		return e
	}
	workers := map[string]*child{}
	defer func() {
		for _, p := range workers {
			p.stop()
		}
	}()
	// Do not load persisted grants on startup: a fresh challenge-response lease is required.
	leasePath := filepath.Join(c.StateDir, "lease.json")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		nonce := Random()
		var signed Signed
		e = request(ctx, client, c, "POST", "/api/node/lease", map[string]string{"node_id": c.NodeID, "nonce": nonce}, &signed)
		if e == nil {
			var l Lease
			l, e = VerifyLease(key, signed, c.NodeID, nonce, time.Now().UTC())
			if e == nil {
				b, _ := json.Marshal(signed)
				e = atomicFile(leasePath, b)
				if e != nil {
					return e
				}
				wanted := map[string]bool{}
				for _, g := range l.Grants {
					if len(g.Tunnels) == 0 {
						continue
					}
					wanted[g.DeviceID] = true
					if p := workers[g.DeviceID]; p != nil {
						select {
						case err := <-p.done:
							p.cleanup()
							delete(workers, g.DeviceID)
							slog.Warn("device guard exited", "device", g.DeviceID, "error", err)
						default:
						}
					}
					if workers[g.DeviceID] == nil {
						p, err := launch(ctx, self, "guard", "--config", configFile, "--device", g.DeviceID)
						if err != nil {
							slog.Error("guard start failed", "error", err)
						} else {
							workers[g.DeviceID] = p
						}
					}
				}
				for id, p := range workers {
					if !wanted[id] {
						p.stop()
						delete(workers, id)
					}
				}
			}
		}
		if e != nil {
			slog.Warn("lease refresh failed; existing grants expire locally", "error", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type guardPolicy struct {
	mu        sync.RWMutex
	grant     Grant
	deadline  time.Time
	authorize func(context.Context, string, string) error
}

func (p *guardPolicy) handler(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	grant, deadline := p.grant, p.deadline
	p.mu.RUnlock()
	deny := func(s string) { JSON(w, 200, map[string]any{"reject": true, "reject_reason": s}) }
	if time.Now().After(deadline) {
		deny("授权租约已到期")
		return
	}
	var req struct {
		Op      string         `json:"op"`
		Content map[string]any `json:"content"`
	}
	if e := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); e != nil {
		deny("请求无效")
		return
	}
	// Fresh authorizations fail closed even while previously established traffic has a finite lease.
	if p.authorize != nil && req.Op != "Ping" {
		name, _ := req.Content["proxy_name"].(string)
		if e := p.authorize(r.Context(), req.Op, name); e != nil {
			deny("控制平台拒绝新授权或暂不可用")
			return
		}
	}
	if time.Now().After(deadline) {
		deny("授权租约已到期")
		return
	}
	if req.Op == "NewProxy" {
		name, _ := req.Content["proxy_name"].(string)
		typ, _ := req.Content["proxy_type"].(string)
		port, _ := req.Content["remote_port"].(float64)
		ok := false
		for _, t := range grant.Tunnels {
			if t.ID == name && t.Protocol == typ && int(port) == t.RemotePort {
				ok = true
				break
			}
		}
		if !ok {
			deny("隧道、协议或端口未授权")
			return
		}
		if req.Content["group"] != nil && req.Content["group"] != "" {
			deny("不允许自定义分组")
			return
		}
		req.Content["bandwidth_limit"] = fmt.Sprintf("%dKB", grant.BandwidthKB)
		req.Content["bandwidth_limit_mode"] = "server"
		JSON(w, 200, map[string]any{"reject": false, "unchange": false, "content": req.Content})
		return
	}
	switch req.Op {
	case "Login", "Ping", "NewWorkConn":
		JSON(w, 200, map[string]bool{"unchange": true})
	case "NewUserConn":
		name, _ := req.Content["proxy_name"].(string)
		for _, t := range grant.Tunnels {
			if name == t.ID {
				JSON(w, 200, map[string]bool{"unchange": true})
				return
			}
		}
		deny("隧道未授权")
	default:
		deny("操作未授权")
	}
}
func readGrant(c Config, device string) (Lease, Grant, error) {
	var l Lease
	var g Grant
	var signed Signed
	b, e := os.ReadFile(filepath.Join(c.StateDir, "lease.json"))
	if e != nil {
		return l, g, e
	}
	if e = json.Unmarshal(b, &signed); e != nil {
		return l, g, e
	}
	payload, e := base64.StdEncoding.DecodeString(signed.Payload)
	if e != nil {
		return l, g, e
	}
	if e = json.Unmarshal(payload, &l); e != nil {
		return l, g, e
	}
	key, e := base64.StdEncoding.DecodeString(c.VerifyKey)
	if e != nil || len(key) != 32 {
		return l, g, errors.New("公钥无效")
	}
	l, e = VerifyLease(key, signed, c.NodeID, l.Nonce, time.Now().UTC())
	if e != nil {
		return l, g, e
	}
	for _, g = range l.Grants {
		if g.DeviceID == device && len(g.Tunnels) > 0 && g.ExpiresAt.After(time.Now()) {
			return l, g, nil
		}
	}
	return l, g, errors.New("设备授权不存在或已到期")
}
func Guard(ctx context.Context, c Config, device string) error {
	l, g, e := readGrant(c, device)
	if e != nil {
		return e
	}
	policy := &guardPolicy{}
	client, e := HTTPClient(c)
	if e != nil {
		return e
	}
	client.Timeout = time.Second
	policy.authorize = func(ctx context.Context, op, proxy string) error {
		var out struct {
			OK bool `json:"ok"`
		}
		e := request(ctx, client, c, "POST", "/api/node/check", map[string]string{"node_id": c.NodeID, "device_id": device, "op": op, "proxy": proxy}, &out)
		if e != nil {
			return e
		}
		if !out.OK {
			return errors.New("新授权被拒绝")
		}
		return nil
	}
	setPolicy := func(l Lease, g Grant) {
		policy.mu.Lock()
		defer policy.mu.Unlock()
		policy.grant = g
		ttl := time.Until(l.Until)
		if d := time.Until(g.ExpiresAt); d < ttl {
			ttl = d
		}
		policy.deadline = time.Now().Add(ttl)
	}
	setPolicy(l, g)
	// Separate listener for each isolated frps; random URL path is not exposed publicly.
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer listener.Close()
	secret := Random()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+secret, policy.handler)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
	defer srv.Close()
	go func() { _ = srv.Serve(listener) }()
	config := ServerConfig(g, c, listener.Addr().String(), secret)
	path := filepath.Join(c.StateDir, "frps-"+device+".toml")
	if e = atomicFile(path, []byte(config)); e != nil {
		return e
	}
	process, e := launch(ctx, c.FRPPath, "-c", path)
	if e != nil {
		return e
	}
	defer func() {
		if process != nil {
			process.stop()
		}
	}()
	slog.Info("grant applied", "device", device, "config_version", Digest(config), "expires_at", g.ExpiresAt)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	lastIssued := l.IssuedAt
	fingerprint := grantFingerprint(g)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-process.done:
			process.cleanup()
			process = nil
			return errors.New("frps 退出；节点将在下次刷新时重启")
		case <-ticker.C:
			now := time.Now()
			policy.mu.RLock()
			deadline := policy.deadline
			policy.mu.RUnlock()
			if !now.Before(deadline) {
				return errors.New("租约或套餐到期，关闭现有连接")
			}
			next, ng, err := readGrant(c, device)
			if err != nil {
				continue
			}
			if !next.IssuedAt.After(lastIssued) {
				continue
			}
			lastIssued = next.IssuedAt
			if grantFingerprint(ng) != fingerprint {
				return errors.New("配置变更，重启隔离实例应用新配置")
			}
			setPolicy(next, ng)
		}
	}
}
func grantFingerprint(g Grant) string {
	g.ExpiresAt = time.Time{}
	b, _ := json.Marshal(g)
	return Digest(string(b))
}
func ServerConfig(g Grant, c Config, plugin, secret string) string {
	// Empty allowPorts means unrestricted in FRP, so guards with no tunnels must never start.
	var b strings.Builder
	fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\nbindPort = %d\nauth.method = \"token\"\nauth.token = %q\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\ntransport.tls.force = true\ntransport.tls.certFile = %q\ntransport.tls.keyFile = %q\ntransport.tcpMux = true\ntransport.maxPoolCount = 10\nmaxPortsPerClient = %d\nlog.to = %q\nlog.level = \"warn\"\nlog.maxDays = 7\nlog.disablePrintColor = true\nallowPorts = [", g.ControlPort, g.Token, filepath.ToSlash(c.TLSCert), filepath.ToSlash(c.TLSKey), len(g.Tunnels), filepath.ToSlash(filepath.Join(c.StateDir, "frps-"+g.DeviceID+".log")))
	for i, t := range g.Tunnels {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "{single = %d}", t.RemotePort)
	}
	fmt.Fprintf(&b, "]\n[[httpPlugins]]\nname = \"policy\"\naddr = %q\npath = %q\nops = [\"Login\", \"NewProxy\", \"NewUserConn\", \"Ping\", \"NewWorkConn\"]\n", plugin, "/"+secret)
	return b.String()
}
func ClientConfig(g Grant, host, ca string) string {
	return ClientConfigWithOptions(g, host, ca, Config{})
}
func ClientConfigWithOptions(g Grant, host, ca string, options Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = %q\nserverPort = %d\nauth.method = \"token\"\nauth.token = %q\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\nloginFailExit = false\ntransport.tls.enable = true\ntransport.tls.serverName = %q\n", host, g.ControlPort, g.Token, host)
	fmt.Fprintf(&b, "transport.protocol = \"tcp\"\ntransport.poolCount = %d\ntransport.tcpMux = %t\n", options.PoolCount, options.TCPMux == nil || *options.TCPMux)
	if ca != "" {
		fmt.Fprintf(&b, "transport.tls.trustedCaFile = %q\n", filepath.ToSlash(ca))
	}
	level := options.LogLevel
	if level == "" {
		level = "error"
	}
	days := options.MaxLogDays
	if days == 0 {
		days = 7
	}
	logTo := "console"
	if options.StateDir != "" {
		logTo = filepath.ToSlash(filepath.Join(options.StateDir, "frpc.log"))
	}
	fmt.Fprintf(&b, "log.to = %q\nlog.level = %q\nlog.maxDays = %d\nlog.disablePrintColor = true\n", logTo, level, days)
	for _, t := range g.Tunnels {
		fmt.Fprintf(&b, "\n[[proxies]]\nname = %q\ntype = %q\nlocalIP = %q\nlocalPort = %d\nremotePort = %d\n", t.ID, t.Protocol, t.LocalHost, t.LocalPort, t.RemotePort)
	}
	return b.String()
}
func BindClient(ctx context.Context, c Config, code, path string) error {
	client, e := HTTPClient(c)
	if e != nil {
		return e
	}
	var out struct {
		DeviceID   string `json:"device_id"`
		Credential string `json:"credential"`
	}
	if e = request(ctx, client, c, "POST", "/api/device/bind", map[string]string{"code": code}, &out); e != nil {
		return e
	}
	c.DeviceID = out.DeviceID
	c.Credential = out.Credential
	if e = SaveConfig(path, c); e != nil {
		return e
	}
	slog.Info("device bound; credential saved in protected config", "device", c.DeviceID)
	return nil
}

type DeviceConfig struct {
	Version       int    `json:"version"`
	Host          string `json:"host"`
	Grant         Grant  `json:"grant"`
	ConfigVersion string `json:"config_version"`
	State         string `json:"state"`
	PublicCA      bool   `json:"public_ca"`
}

func Agent(ctx context.Context, c Config) error {
	if e := validateFRP(c.FRPPath, "frpc"); e != nil {
		return e
	}
	if c.CAFile != "" {
		if _, e := os.Stat(c.CAFile); e != nil {
			return e
		}
	}
	client, e := HTTPClient(c)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return e
	}
	var process *child
	defer func() {
		if process != nil {
			process.stop()
		}
	}()
	last := ""
	failures := 0
	for {
		var dc DeviceConfig
		e = request(ctx, client, c, "GET", "/api/device/config", nil, &dc)
		if e != nil {
			failures++
			if process != nil {
				process.stop()
				process = nil
				last = ""
			}
			slog.Warn("device configuration unavailable", "error", e)
		} else {
			failures = 0
			ca := c.CAFile
			if dc.PublicCA {
				ca = ""
			} else if ca == "" {
				return errors.New("此节点使用平台私有 CA，请重新运行 connect 下载信任证书")
			}
			config := ClientConfigWithOptions(dc.Grant, dc.Host, ca, c)
			hash := Digest(config)
			if process != nil {
				select {
				case err := <-process.done:
					process.cleanup()
					process = nil
					last = ""
					slog.Warn("frpc exited", "error", err)
				default:
				}
			}
			if len(dc.Grant.Tunnels) == 0 {
				if process != nil {
					process.stop()
					process = nil
				}
				last = ""
			} else if hash != last || process == nil {
				if process != nil {
					process.stop()
					process = nil
				}
				path := filepath.Join(c.StateDir, "frpc.toml")
				if e = atomicFile(path, []byte(config)); e != nil {
					return e
				}
				process, e = launch(ctx, c.FRPPath, "-c", path)
				if e != nil {
					return e
				}
				last = hash
				slog.Info("client configuration applied", "config_version", dc.ConfigVersion, "device", dc.Grant.DeviceID)
			}
		}
		delay := 3 * time.Second
		if failures > 0 {
			n := failures
			if n > 4 {
				n = 4
			}
			delay = time.Duration(1<<n) * time.Second
		}
		delay += time.Duration(rand.IntN(500)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func Diagnose(ctx context.Context, c Config) error {
	client, e := HTTPClient(c)
	if e != nil {
		return e
	}
	var dc DeviceConfig
	if e = request(ctx, client, c, "GET", "/api/device/config", nil, &dc); e != nil {
		return e
	}
	ips, e := net.DefaultResolver.LookupHost(ctx, dc.Host)
	if e != nil {
		return fmt.Errorf("DNS 失败: %w", e)
	}
	slog.Info("node DNS resolved", "host", dc.Host, "addresses", ips)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dc.Host, fmt.Sprint(dc.Grant.ControlPort)))
	if e != nil {
		return fmt.Errorf("节点控制端口连接失败（请检查已创建隧道、节点状态和防火墙）: %w", e)
	}
	conn.Close()
	for _, t := range dc.Grant.Tunnels {
		if t.Protocol == "tcp" {
			conn, e = dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.LocalHost, fmt.Sprint(t.LocalPort)))
			if e != nil {
				slog.Warn("local service unavailable", "tunnel", t.ID, "error", e)
			} else {
				conn.Close()
				slog.Info("local service reachable", "tunnel", t.ID)
			}
		} else {
			slog.Info("UDP 服务需要应用层响应测试", "tunnel", t.ID)
		}
	}
	return nil
}
