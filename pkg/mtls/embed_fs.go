package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
)

type EmbedFS struct {
	embedFS    *embed.FS
	embedDir   string
	serverName string
}

// SetEfsCertsDir 设置证书目录
func (t *EmbedFS) SetEmbedDir(path string) *EmbedFS {
	if path[len(path)-1] != '/' {
		path += "/"
	}
	t.embedDir = path
	return t
}

// SetServerName
func (t *EmbedFS) SetServerName(serverName string) *EmbedFS {
	t.serverName = serverName
	return t
}

func (t *EmbedFS) X509KeyPair(name string) (tls.Certificate, error) {
	nilv := tls.Certificate{}
	certPEM, err := t.embedFS.ReadFile(t.embedDir + name + ".crt")
	if err != nil {
		return nilv, fmt.Errorf("无法读取服务器证书: %v", err)
	}

	keyPEM, err := t.embedFS.ReadFile(t.embedDir + name + ".key")
	if err != nil {
		return nilv, fmt.Errorf("无法读取服务器密钥: %v", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (t *EmbedFS) CertPool() (*x509.CertPool, error) {
	caPEM, err := t.embedFS.ReadFile(t.embedDir + "ca.crt")
	if err != nil {
		return nil, fmt.Errorf("无法读取CA证书: %v", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("无法添加CA证书到证书池")
	}
	return certPool, nil
}

func (t *EmbedFS) ServerTLSConfig() (*tls.Config, error) {
	name := "server"
	cert, err := t.X509KeyPair(name)
	if err != nil {
		return nil, fmt.Errorf("无法创建TLS证书: %v", err)
	}
	certPool, err := t.CertPool()
	if err != nil {
		return nil, fmt.Errorf("无法创建TLS证书池: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}, nil
}

func (t *EmbedFS) ClientTLSConfig() (*tls.Config, error) {
	name := "client"
	cert, err := t.X509KeyPair(name)
	if err != nil {
		return nil, fmt.Errorf("无法创建TLS证书: %v", err)
	}
	certPool, err := t.CertPool()
	if err != nil {
		return nil, fmt.Errorf("无法创建TLS证书池: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		ServerName:   t.serverName,
		// InsecureSkipVerify: true, // 不验证主机名，解决IP地址连接问题
	}, nil
}

func NewEmbedFS(embedfs *embed.FS) *EmbedFS {
	t := &EmbedFS{
		embedFS:    embedfs,
		embedDir:   "embed/certs/",
		serverName: "localhost",
	}
	return t
}
