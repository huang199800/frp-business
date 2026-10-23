package platform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, v := range []struct{ old, want time.Time }{{now.Add(time.Hour), now.Add(2 * time.Hour)}, {now.Add(-time.Hour), now.Add(time.Hour)}, {time.Time{}, now.Add(time.Hour)}} {
		if got := NextExpiry(v.old, now, 3600); !got.Equal(v.want) {
			t.Fatalf("expiry: %v != %v", got, v.want)
		}
	}
}
func TestTOTPVector(t *testing.T) { // RFC 6238 SHA-1 vector, truncated to six digits.
	if got := TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)); got != "287082" {
		t.Fatal(got)
	}
}
func TestLeaseSecurity(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	l := Lease{Version: 1, NodeID: "node", Nonce: Random(), IssuedAt: now, Until: now.Add(15 * time.Second)}
	s := SignLease(key, l)
	if _, e := VerifyLease(pub, s, l.NodeID, l.Nonce, now); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct {
		node, nonce string
		at          time.Time
	}{{"other", l.Nonce, now}, {l.NodeID, "replayed-challenge", now}, {l.NodeID, l.Nonce, now.Add(16 * time.Second)}} {
		if _, e := VerifyLease(pub, s, v.node, v.nonce, v.at); e == nil {
			t.Fatal("invalid lease accepted")
		}
	}
	b, _ := base64.StdEncoding.DecodeString(s.Payload)
	b[len(b)/2] ^= 1
	s.Payload = base64.StdEncoding.EncodeToString(b)
	if _, e := VerifyLease(pub, s, l.NodeID, l.Nonce, now); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestPluginEnforcement(t *testing.T) {
	p := guardPolicy{deadline: time.Now().Add(time.Minute), grant: Grant{BandwidthKB: 100, Tunnels: []Tunnel{{ID: "paid", Protocol: "tcp", RemotePort: 20000}}}}
	for _, v := range []struct {
		name, typ string
		port      int
		reject    bool
	}{{"paid", "tcp", 20000, false}, {"paid", "udp", 20000, true}, {"paid", "tcp", 20001, true}, {"forged", "tcp", 20000, true}} {
		req := httptest.NewRequest("POST", "/", strings.NewReader(fmt.Sprintf(`{"op":"NewProxy","content":{"proxy_name":%q,"proxy_type":%q,"remote_port":%d,"bandwidth_limit":"999999KB","bandwidth_limit_mode":"client"}}`, v.name, v.typ, v.port)))
		w := httptest.NewRecorder()
		p.handler(w, req)
		var out struct {
			Reject  bool           `json:"reject"`
			Content map[string]any `json:"content"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		if out.Reject != v.reject {
			t.Fatal(w.Body.String())
		}
		if !v.reject && (out.Content["bandwidth_limit"] != "100KB" || out.Content["bandwidth_limit_mode"] != "server") {
			t.Fatal("server limit not forced")
		}
	}
}
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("FRP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("设置 FRP_TEST_DATABASE_URL 以运行 PostgreSQL 集成测试")
	}
	ctx := context.Background()
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	schema := "test_" + strings.ToLower(Random())
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 32
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s := &Store{db, key}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	return s
}
func seedUser(t *testing.T, s *Store) string {
	t.Helper()
	id := Random()
	_, e := s.DB.Exec(context.Background(), "INSERT INTO users(id,email,password,role) VALUES($1,$2,'x','user')", id, id+"@test.invalid")
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func seedPlan(t *testing.T, s *Store) string {
	t.Helper()
	ctx := context.Background()
	node, plan := Random(), Random()
	_, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,host,token_hash,control_start,control_end,port_start,port_end) VALUES($1,'test','localhost','x',17000,17999,20000,20999)", node)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO plans(id,name,node_id,max_devices,max_tunnels,tunnel_kibps) VALUES($1,'test',$2,16,128,1024)", plan, node)
	if e != nil {
		t.Fatal(e)
	}
	return plan
}
func seedCard(t *testing.T, s *Store, user, plan string, seconds int64) string {
	t.Helper()
	batch, code := Random(), Random()
	ctx := context.Background()
	_, e := s.DB.Exec(ctx, "INSERT INTO batches(id,name,note,plan_id,seconds,deadline,created_by) VALUES($1,'test','',$2,$3,clock_timestamp()+interval '1 day',$4)", batch, plan, seconds, user)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO cards(hash,batch_id) VALUES($1,$2)", Digest(code), batch)
	if e != nil {
		t.Fatal(e)
	}
	return code
}
func TestPostgresConcurrentRedemption(t *testing.T) {
	s := testStore(t)
	user := seedUser(t, s)
	plan := seedPlan(t, s)
	code := seedCard(t, s, user, plan, 3600)
	ctx := context.Background()
	var wg sync.WaitGroup
	var successes atomic.Int32
	out := make(chan Redemption, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.Redeem(ctx, user, Group(strings.ToLower(code)), Random())
			if e != nil {
				t.Error(e)
				return
			}
			successes.Add(1)
			out <- r
		}()
	}
	wg.Wait()
	close(out)
	if successes.Load() != 40 {
		t.Fatal("some retries failed")
	}
	var first time.Time
	for r := range out {
		if first.IsZero() {
			first = r.After
		}
		if !first.Equal(r.After) {
			t.Fatal("duplicate credit")
		}
	}
	var count int
	if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM redemptions").Scan(&count); e != nil || count != 1 {
		t.Fatalf("rows=%d err=%v", count, e)
	}
	second := seedUser(t, s)
	if _, e := s.Redeem(ctx, second, code, Random()); e == nil {
		t.Fatal("card reused across accounts")
	}
	code2 := seedCard(t, s, user, plan, 3600)
	r, e := s.Redeem(ctx, user, code2, "stable-request")
	if e != nil {
		t.Fatal(e)
	}
	if !r.After.Equal(first.Add(time.Hour)) {
		t.Fatal("unexpired renewal wrong")
	}
	repeat, e := s.Redeem(ctx, user, code2, "stable-request")
	if e != nil || !repeat.Repeated || !repeat.After.Equal(r.After) {
		t.Fatal("response-loss retry failed")
	}
	if _, e = s.Redeem(ctx, user, code, "stable-request"); e == nil {
		t.Fatal("request id reused for different card")
	}
	other := seedPlan(t, s)
	if _, e = s.Redeem(ctx, user, seedCard(t, s, user, other, 3600), Random()); e == nil {
		t.Fatal("cross-plan redemption accepted")
	}
	if _, e = s.DB.Exec(ctx, "UPDATE entitlements SET expires_at=clock_timestamp()-interval '1 day' WHERE user_id=$1", user); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	r, e = s.Redeem(ctx, user, seedCard(t, s, user, plan, 3600), Random())
	if e != nil || r.After.Sub(start) < time.Hour || r.After.Sub(start) > time.Hour+3*time.Second {
		t.Fatalf("expired renewal %v %v", r, e)
	}
}
func TestPostgresCompetingUsersAndPorts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	plan := seedPlan(t, s)
	owner := seedUser(t, s)
	shared := seedCard(t, s, owner, plan, 3600)
	var won atomic.Int32
	var wg sync.WaitGroup
	users := make([]string, 20)
	for i := range users {
		users[i] = seedUser(t, s)
	}
	for _, u := range users {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if _, e := s.Redeem(ctx, u, shared, Random()); e == nil {
				won.Add(1)
			}
		}(u)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("winners=%d", won.Load())
	}
	// All users now get independent cards, bind simultaneously, allocate unique business ports.
	for _, u := range users {
		if _, e := s.Redeem(ctx, u, seedCard(t, s, u, plan, 3600), Random()); e != nil {
			t.Fatal(e)
		}
	}
	ports := sync.Map{}
	for _, u := range users {
		code := Random()
		if _, e := s.DB.Exec(ctx, "INSERT INTO bind_codes(hash,user_id,name,expires_at) VALUES($1,$2,'test',clock_timestamp()+interval '5 minutes')", Digest(code), u); e != nil {
			t.Fatal(e)
		}
		wg.Add(1)
		go func(u, code string) {
			defer wg.Done()
			d, e := s.Bind(ctx, code)
			if e != nil {
				t.Error(e)
				return
			}
			tun, e := s.CreateTunnel(ctx, u, Tunnel{Name: "t", DeviceID: d["device_id"], Protocol: "tcp", LocalHost: "127.0.0.1", LocalPort: 22})
			if e != nil {
				t.Error(e)
				return
			}
			if _, loaded := ports.LoadOrStore(tun.RemotePort, true); loaded {
				t.Error("port allocated twice")
			}
			if _, e = s.CreateTunnel(ctx, owner, Tunnel{Name: "steal", DeviceID: d["device_id"], Protocol: "tcp", LocalHost: "127.0.0.1", LocalPort: 22}); e == nil {
				t.Error("cross-tenant tunnel accepted")
			}
		}(u, code)
	}
	wg.Wait()
}
func TestHTTPIsolationAndCSRF(t *testing.T) {
	s := testStore(t)
	u := seedUser(t, s)
	v := seedUser(t, s)
	ctx := context.Background()
	token := Random()
	_, e := s.DB.Exec(ctx, "INSERT INTO sessions(hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')", Digest(token), u)
	if e != nil {
		t.Fatal(e)
	}
	a := NewAPI(s, Config{PublicURL: "https://portal.test"}, os.DirFS("."))
	for _, path := range []string{"/api/admin/overview", "/api/devices/" + v + "/revoke"} {
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code >= 200 && w.Code < 300 {
			t.Fatal("unauthorized mutation")
		}
	}
	r := httptest.NewRequest("POST", "/api/logout", strings.NewReader("{}"))
	r.Header.Set("Cookie", "session="+token)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		b, _ := io.ReadAll(w.Result().Body)
		t.Fatal(w.Code, string(b))
	}
}

func TestMigrationRefusesIncompatibleDowngrade(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, e := s.DB.Exec(ctx, "INSERT INTO schema_versions(version) VALUES(2)"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e == nil {
		t.Fatal("incompatible database accepted")
	}
}
func TestReleaseTamperingRejected(t *testing.T) {
	dir := t.TempDir()
	if e := ReleaseKeygen(dir); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "portal")
	data := []byte("test binary")
	if e := os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	manifest := filepath.Join(dir, "SHA256SUMS")
	if e := os.WriteFile(manifest, []byte(Digest(string(data))+"  portal\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := SignRelease(filepath.Join(dir, "release-private.key"), manifest); e != nil {
		t.Fatal(e)
	}
	if e := VerifyRelease(filepath.Join(dir, "release-public.key"), manifest); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file, []byte("modified"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := VerifyRelease(filepath.Join(dir, "release-public.key"), manifest); e == nil {
		t.Fatal("tampered release accepted")
	}
	if e := os.WriteFile(manifest, []byte(Digest(string(data))+"  ../outside\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := SignRelease(filepath.Join(dir, "release-private.key"), manifest); e != nil {
		t.Fatal(e)
	}
	if e := VerifyRelease(filepath.Join(dir, "release-public.key"), manifest); e == nil {
		t.Fatal("path traversal accepted")
	}
}
