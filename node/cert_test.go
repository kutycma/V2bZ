package node

import (
	"path/filepath"
	"testing"
)

func Test_generateSelfSslCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "cert.key")
	if err := generateSelfSslCertificate("domain.com", certPath, keyPath); err != nil {
		t.Fatalf("generate self-signed certificate: %v", err)
	}
}
