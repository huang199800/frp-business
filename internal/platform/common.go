package platform

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const Version = "0.2.0"
const FRPVersion = "0.71.1"
const LeaseSeconds = 15

type Config struct {
	Listen          string `json:"listen"`
	DatabaseURL     string `json:"database_url"`
	PublicURL       string `json:"public_url"`
	TLSCert         string `json:"tls_cert"`
	TLSKey          string `json:"tls_key"`
	DevHTTP         bool   `json:"dev_http"`
	ReverseProxyTLS bool   `json:"reverse_proxy_tls"`
	SigningSeed     string `json:"signing_seed"`
	// Node/agent
	ControlURL   string `json:"control_url"`
	Credential   string `json:"credential"`
	NodeID       string `json:"node_id"`
	VerifyKey    string `json:"verify_key"`
	FRPPath      string `json:"frp_path"`
	StateDir     string `json:"state_dir"`
	PublicHost   string `json:"public_host"`
	PluginListen string `json:"plugin_listen"`
	CAFile       string `json:"ca_file"`
	DeviceID     string `json:"device_id"`
	PoolCount    int    `json:"pool_count,omitempty"`
	TCPMux       *bool  `json:"tcp_mux,omitempty"`
	LogLevel     string `json:"log_level,omitempty"`
	MaxLogDays   int    `json:"max_log_days,omitempty"`
}

func ReadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	e = d.Decode(&c)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.PluginListen == "" {
		c.PluginListen = "127.0.0.1:19090"
	}
	return c, e
}
func SaveConfig(path string, c Config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func Random() string {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func Digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func Normalize(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(s))
}
func Group(s string) string {
	var a []string
	for len(s) > 8 {
		a = append(a, s[:8])
		s = s[8:]
	}
	return strings.Join(append(a, s), "-")
}
func NextExpiry(before, now time.Time, seconds int64) time.Time {
	if before.Before(now) {
		before = now
	}
	return before.Add(time.Duration(seconds) * time.Second)
}
func TOTP(secret string, t time.Time) string {
	b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30))
	h := hmac.New(sha1.New, b)
	h.Write(counter[:])
	v := h.Sum(nil)
	o := v[len(v)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(v[o:o+4])&0x7fffffff)%1000000)
}
func CheckTOTP(s, code string) bool {
	if len(code) != 6 || s == "" {
		return false
	}
	for i := -1; i <= 1; i++ {
		if hmac.Equal([]byte(TOTP(s, time.Now().Add(time.Duration(i)*30*time.Second))), []byte(code)) {
			return true
		}
	}
	return false
}
func SigningKey(seed string) (ed25519.PrivateKey, error) {
	b, e := base64.StdEncoding.DecodeString(seed)
	if e != nil || len(b) != 32 {
		return nil, errors.New("signing_seed 必须为 32 字节 Base64")
	}
	return ed25519.NewKeyFromSeed(b), nil
}
func DeviceFRPToken(key ed25519.PrivateKey, id string, generation int) string {
	h := hmac.New(sha256.New, key.Seed())
	fmt.Fprintf(h, "device:%s:%d", id, generation)
	return hex.EncodeToString(h.Sum(nil))
}

type Tunnel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	LocalHost  string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port"`
	Paused     bool   `json:"paused"`
	DeviceID   string `json:"device_id"`
}
type Grant struct {
	DeviceID    string    `json:"device_id"`
	ControlPort int       `json:"control_port"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	BandwidthKB int       `json:"bandwidth_kb"`
	Tunnels     []Tunnel  `json:"tunnels"`
}
type Lease struct {
	Version  int       `json:"version"`
	NodeID   string    `json:"node_id"`
	Nonce    string    `json:"nonce"`
	IssuedAt time.Time `json:"issued_at"`
	Until    time.Time `json:"until"`
	Grants   []Grant   `json:"grants"`
}
type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func SignLease(key ed25519.PrivateKey, l Lease) Signed {
	b, _ := json.Marshal(l)
	return Signed{base64.StdEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}
}
func VerifyLease(key ed25519.PublicKey, s Signed, node, nonce string, now time.Time) (Lease, error) {
	var l Lease
	b, e := base64.StdEncoding.DecodeString(s.Payload)
	sig, e2 := base64.StdEncoding.DecodeString(s.Signature)
	if e != nil || e2 != nil || !ed25519.Verify(key, b, sig) {
		return l, errors.New("租约签名错误")
	}
	if e = json.Unmarshal(b, &l); e != nil {
		return l, e
	}
	if l.Version != 1 || l.NodeID != node || l.Nonce != nonce || !l.Until.After(now) || l.Until.Sub(now) > 16*time.Second || l.IssuedAt.After(now.Add(time.Second)) || l.Until.Sub(l.IssuedAt) > LeaseSeconds*time.Second {
		return l, errors.New("租约过期、时钟偏差或身份不匹配")
	}
	return l, nil
}
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type APIError struct {
	Status  int
	Message string
}

func (e APIError) Error() string { return e.Message }
func Bad(s string) error         { return APIError{400, s} }
func Deny(s string) error        { return APIError{403, s} }
func decode(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return Bad("请使用 application/json")
	}
	d := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return Bad("JSON 参数无效")
	}
	var extra any
	if errors.Is(d.Decode(&extra), io.EOF) {
		return nil
	}
	return Bad("多余 JSON 数据")
}
