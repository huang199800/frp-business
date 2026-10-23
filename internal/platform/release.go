package platform

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Release signing uses an independent offline key, never the authorization key.
func ReleaseKeygen(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	private := filepath.Join(dir, "release-private.key")
	public := filepath.Join(dir, "release-public.key")
	for _, p := range []string{private, public} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			return errors.New("发布密钥文件已存在，拒绝覆盖")
		}
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	if e = os.WriteFile(private, []byte(base64.StdEncoding.EncodeToString(key.Seed())+"\n"), 0600); e != nil {
		return e
	}
	return os.WriteFile(public, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644)
}
func SignRelease(keyFile, manifest string) error {
	raw, e := os.ReadFile(keyFile)
	if e != nil {
		return e
	}
	key, e := SigningKey(strings.TrimSpace(string(raw)))
	if e != nil {
		return e
	}
	b, e := os.ReadFile(manifest)
	if e != nil {
		return e
	}
	return os.WriteFile(manifest+".sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))+"\n"), 0644)
}
func VerifyRelease(keyFile, manifest string) error {
	keyData, e := os.ReadFile(keyFile)
	if e != nil {
		return e
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if e != nil || len(key) != 32 {
		return errors.New("发布公钥无效")
	}
	b, e := os.ReadFile(manifest)
	if e != nil {
		return e
	}
	sigData, e := os.ReadFile(manifest + ".sig")
	if e != nil {
		return e
	}
	sig, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if e != nil || !ed25519.Verify(key, b, sig) {
		return errors.New("发布签名无效")
	}
	root, e := filepath.Abs(filepath.Dir(manifest))
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return errors.New("校验清单格式无效")
		}
		name := strings.TrimPrefix(fields[1], "*")
		// Artifact names are flat, ASCII, and never traversed or interpreted as shell commands.
		if filepath.Base(name) != name || strings.ContainsAny(name, "/\\:") || name == "." || name == ".." || seen[name] {
			return errors.New("清单路径无效或重复")
		}
		seen[name] = true
		want, e := hex.DecodeString(fields[0])
		if e != nil || len(want) != 32 {
			return errors.New("SHA256 无效")
		}
		path := filepath.Join(root, name)
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("仅允许校验普通文件")
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if Digest(string(data)) != strings.ToLower(fields[0]) {
			return fmt.Errorf("文件校验失败: %s", name)
		}
		lines++
	}
	if lines == 0 {
		return errors.New("校验清单为空")
	}
	return nil
}
