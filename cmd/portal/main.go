package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"example.com/frp-business/internal/platform"
)

//go:embed all:ui
var ui embed.FS
var closeLog func() error

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := entry(); err != nil {
		slog.Error("退出", "error", err)
		if closeLog != nil {
			_ = closeLog()
		}
		os.Exit(1)
	}
	if closeLog != nil {
		_ = closeLog()
	}
}
func entry() error {
	if len(os.Args) < 2 {
		return errors.New("用法: portal version|init|migrate|bootstrap|serve|node|bind|agent|diagnose|guard|dev-cert [参数]")
	}
	command := os.Args[1]
	if command == "version" {
		fmt.Printf("portal %s; frp %s\n", platform.Version, platform.FRPVersion)
		return nil
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	path := f.String("config", "control.json", "配置文件")
	dir := f.String("dir", ".", "初始化目录")
	email := f.String("email", "", "管理员邮箱")
	code := f.String("code", "", "一次性设备绑定码（建议通过标准输入）")
	device := f.String("device", "", "内部设备 ID")
	host := f.String("host", "localhost", "开发证书 DNS/IP")
	public := f.String("public-url", "https://portal.example.com", "控制台公网 URL")
	asService := f.Bool("service", false, "作为 Windows Service 运行")
	logPath := f.String("log-file", "", "轮转日志文件（每份 10 MiB，保留 3 份历史）")
	keyPath := f.String("key", "", "独立发布签名密钥 / 验证公钥")
	manifest := f.String("manifest", "SHA256SUMS", "发布校验清单")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if *logPath != "" {
		writer, e := platform.OpenLog(*logPath)
		if e != nil {
			return e
		}
		closeLog = writer.Close
		platform.LogOutput = writer
		slog.SetDefault(slog.New(slog.NewJSONHandler(writer, nil)))
	}
	switch command {
	case "release-keygen":
		return platform.ReleaseKeygen(*dir)
	case "release-sign":
		return platform.SignRelease(*keyPath, *manifest)
	case "verify":
		if e := platform.VerifyRelease(*keyPath, *manifest); e != nil {
			return e
		}
		fmt.Println("签名与文件校验通过")
		return nil
	}
	if command == "init" {
		if e := os.MkdirAll(*dir, 0700); e != nil {
			return e
		}
		target := filepath.Join(*dir, "control.json")
		if _, e := os.Stat(target); !os.IsNotExist(e) {
			return errors.New("control.json 已存在，拒绝覆盖")
		}
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		c := platform.Config{Listen: "127.0.0.1:8080", DatabaseURL: os.Getenv("FRP_DATABASE_URL"), PublicURL: *public, SigningSeed: base64.StdEncoding.EncodeToString(key.Seed())}
		if c.DatabaseURL == "" {
			return errors.New("先设置 FRP_DATABASE_URL，避免在命令行参数中暴露数据库密码")
		}
		if e = platform.SaveConfig(target, c); e != nil {
			return e
		}
		fmt.Println("控制配置已创建:", target)
		fmt.Println("节点验证公钥:", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	if command == "dev-cert" {
		return devCert(*dir, *host)
	}
	c, e := platform.ReadConfig(*path)
	if e != nil {
		return e
	}
	run := func(ctx context.Context) error {
		switch command {
		case "serve":
			assets, _ := fs.Sub(ui, "ui")
			return platform.Serve(ctx, c, assets)
		case "node":
			return platform.Node(ctx, c)
		case "guard":
			return platform.Guard(ctx, c, *device)
		case "agent":
			return platform.Agent(ctx, c)
		case "diagnose":
			return platform.Diagnose(ctx, c)
		case "bind":
			if *code == "" {
				fmt.Fprintln(os.Stderr, "输入绑定码:")
				v, e := bufio.NewReader(os.Stdin).ReadString('\n')
				if e != nil && v == "" {
					return e
				}
				*code = strings.TrimSpace(v)
			}
			return platform.BindClient(ctx, c, *code, *path)
		case "migrate", "bootstrap":
			s, e := platform.Open(ctx, c)
			if e != nil {
				return e
			}
			defer s.DB.Close()
			if e = s.Migrate(ctx); e != nil {
				return e
			}
			if command == "migrate" {
				return nil
			}
			if *email == "" {
				return errors.New("需要 --email")
			}
			fmt.Fprintln(os.Stderr, "从标准输入读取管理员密码（终端直接输入可能回显，参见手册的隐藏输入命令）:")
			password, e := bufio.NewReader(os.Stdin).ReadString('\n')
			if e != nil && password == "" {
				return e
			}
			secret, e := s.Bootstrap(ctx, strings.ToLower(*email), strings.TrimSpace(password))
			if e != nil {
				return e
			}
			fmt.Println("双因素密钥（仅显示一次，请录入认证器并离线备份）:", secret)
			fmt.Println("otpauth://totp/FRP-Portal:" + *email + "?secret=" + secret + "&issuer=FRP-Portal")
			return nil
		default:
			return fmt.Errorf("未知命令: %s", command)
		}
	}
	if *asService {
		return runWindowsService(command, run)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return run(ctx)
}
func devCert(dir, host string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	certPath, keyPath := filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	if _, e := os.Stat(certPath); !os.IsNotExist(e) {
		return errors.New("证书文件已存在，拒绝覆盖")
	}
	if _, e := os.Stat(keyPath); !os.IsNotExist(e) {
		return errors.New("私钥已存在，拒绝覆盖")
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "FRP Development Only"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		return e
	}
	fmt.Println("仅供开发测试的证书:", certPath)
	return nil
}
