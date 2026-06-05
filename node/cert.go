package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kutycma/V2bZ/api/panel"
	"github.com/kutycma/V2bZ/conf"
	vCore "github.com/kutycma/V2bZ/core"
	log "github.com/sirupsen/logrus"
)

const (
	domainRenewBefore = 30 * 24 * time.Hour
	ipRenewBefore     = 72 * time.Hour
)

type certMetadata struct {
	Target    string `json:"target"`
	Mode      string `json:"mode"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	NotAfter  int64  `json:"not_after"`
	UpdatedAt int64  `json:"updated_at"`
}

func (c *Controller) renewCertTask() error {
	if err := c.requestCertAndReport(true); err != nil {
		log.WithField("tag", c.tag).Info("renew cert error: ", err)
		return nil
	}
	return nil
}

func (c *Controller) requestCertAndReport(reloadOnChange bool) error {
	previous, _ := c.readCertMetadata()
	meta, err := c.requestCert()
	c.reportCertStatus(meta, err)
	if reloadOnChange && err == nil && certMetadataChanged(previous, meta) {
		c.reloadNodeAfterCertChange()
	}
	return err
}

func (c *Controller) requestCert() (*certMetadata, error) {
	cert := c.currentCertConfig()
	if cert == nil {
		return nil, nil
	}
	cert.CertMode = strings.ToLower(strings.TrimSpace(cert.CertMode))
	cert.CertDomain = normalizeCertTarget(cert.CertDomain)
	if cert.Email == "" {
		cert.Email = "node@zicboard.local"
	}

	switch cert.CertMode {
	case "none", "":
		return nil, nil
	case "file":
		if err := validateCertPaths(cert); err != nil {
			return basicCertMetadata(cert, "file"), err
		}
		if err := ensureCertFilesExist(cert); err != nil {
			return basicCertMetadata(cert, "file"), err
		}
		return metadataFromCertFile(cert, "file")
	case "dns", "http":
		return c.requestManagedCert(cert, cert.CertMode, managedCertSource(cert.CertMode, cert.CertDomain), false)
	case "auto":
		return c.requestAutoCert(cert)
	case "self":
		return c.requestSelfCert(cert)
	default:
		return basicCertMetadata(cert, ""), fmt.Errorf("CertMode không hỗ trợ: %s", cert.CertMode)
	}
}

func (c *Controller) currentCertConfig() *conf.CertConfig {
	if c.activeOptions != nil && c.activeOptions.CertConfig != nil {
		return cloneCertConfig(c.activeOptions.CertConfig)
	}
	return cloneCertConfig(c.CertConfig)
}

func (c *Controller) requestManagedCert(cert *conf.CertConfig, challengeMode, source string, allowSelfSigned bool) (*certMetadata, error) {
	if err := validateCertPaths(cert); err != nil {
		return basicCertMetadata(cert, source), err
	}
	if cert.CertDomain == "" {
		return basicCertMetadata(cert, source), fmt.Errorf("cert target đang trống cho CertMode %s", cert.CertMode)
	}
	ready, _, err := certificateReady(cert, renewBefore(cert.CertDomain), allowSelfSigned)
	if err != nil {
		return basicCertMetadata(cert, source), err
	}
	if ready {
		meta, err := metadataFromCertFile(cert, source)
		if err == nil {
			_ = c.writeCertMetadata(meta)
		}
		return meta, err
	}

	x509Cert, err := issueLegoCert(cert, challengeMode)
	if err != nil {
		return basicCertMetadata(cert, source), fmt.Errorf("tạo chứng chỉ lego lỗi: %s", err)
	}
	meta := metadataFromCertificate(cert, x509Cert, source)
	_ = c.writeCertMetadata(meta)
	return meta, nil
}

func (c *Controller) requestAutoCert(cert *conf.CertConfig) (*certMetadata, error) {
	if err := validateCertPaths(cert); err != nil {
		return basicCertMetadata(cert, "auto"), err
	}
	if err := validateAutoCertTarget(cert.CertDomain); err != nil {
		return basicCertMetadata(cert, "auto"), err
	}

	challengeMode, source := autoCertChallenge(cert)
	ready, _, err := certificateReady(cert, renewBefore(cert.CertDomain), false)
	if err != nil {
		return basicCertMetadata(cert, source), err
	}
	if ready {
		meta, err := metadataFromCertFile(cert, source)
		if err == nil {
			_ = c.writeCertMetadata(meta)
		}
		return meta, err
	}

	x509Cert, issueErr := issueLegoCert(cert, challengeMode)
	if issueErr == nil {
		meta := metadataFromCertificate(cert, x509Cert, source)
		_ = c.writeCertMetadata(meta)
		return meta, nil
	}

	if !cert.SelfFallback {
		return basicCertMetadata(cert, source), fmt.Errorf("tạo chứng chỉ lego lỗi: %s", issueErr)
	}
	log.WithFields(log.Fields{
		"tag":    c.tag,
		"target": cert.CertDomain,
		"mode":   challengeMode,
		"err":    issueErr,
	}).Warn("ACME cert issue failed, falling back to self-signed cert")
	return c.generateAndStoreSelfCert(cert)
}

func (c *Controller) requestSelfCert(cert *conf.CertConfig) (*certMetadata, error) {
	if err := validateCertPaths(cert); err != nil {
		return basicCertMetadata(cert, "self"), err
	}
	if cert.CertDomain == "" {
		return basicCertMetadata(cert, "self"), fmt.Errorf("cert target đang trống cho CertMode self")
	}
	ready, _, err := certificateReady(cert, domainRenewBefore, true)
	if err != nil {
		return basicCertMetadata(cert, "self"), err
	}
	if ready {
		meta, err := metadataFromCertFile(cert, "self")
		if err == nil {
			_ = c.writeCertMetadata(meta)
		}
		return meta, err
	}
	return c.generateAndStoreSelfCert(cert)
}

func (c *Controller) generateAndStoreSelfCert(cert *conf.CertConfig) (*certMetadata, error) {
	if err := generateSelfSslCertificate(cert.CertDomain, cert.CertFile, cert.KeyFile); err != nil {
		return basicCertMetadata(cert, "self"), fmt.Errorf("tạo chứng chỉ self-signed lỗi: %s", err)
	}
	x509Cert, err := loadCertificate(cert)
	if err != nil {
		return basicCertMetadata(cert, "self"), err
	}
	meta := metadataFromCertificate(cert, x509Cert, "self")
	_ = c.writeCertMetadata(meta)
	return meta, nil
}

func issueLegoCert(cert *conf.CertConfig, challengeMode string) (*x509.Certificate, error) {
	legoCert := *cert
	legoCert.CertMode = challengeMode
	legoCert.DNSEnv = cloneDNSEnv(cert.DNSEnv)
	l, err := NewLego(&legoCert)
	if err != nil {
		return nil, fmt.Errorf("tạo lego object lỗi: %s", err)
	}
	if err := l.CreateCert(); err != nil {
		return nil, err
	}
	return loadCertificate(cert)
}

func validateCertPaths(cert *conf.CertConfig) error {
	if cert.CertFile == "" || cert.KeyFile == "" {
		return fmt.Errorf("thiếu đường dẫn cert file hoặc key file")
	}
	return nil
}

func ensureCertFilesExist(cert *conf.CertConfig) error {
	if _, err := os.Stat(cert.CertFile); err != nil {
		return fmt.Errorf("không tìm thấy cert file %s: %w", cert.CertFile, err)
	}
	if _, err := os.Stat(cert.KeyFile); err != nil {
		return fmt.Errorf("không tìm thấy key file %s: %w", cert.KeyFile, err)
	}
	return nil
}

func certificateReady(cert *conf.CertConfig, minValidity time.Duration, allowSelfSigned bool) (bool, *x509.Certificate, error) {
	if err := ensureCertFilesExist(cert); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, err
	}
	x509Cert, err := loadCertificate(cert)
	if err != nil {
		return false, nil, nil
	}
	now := time.Now()
	if now.Before(x509Cert.NotBefore) || time.Until(x509Cert.NotAfter) <= minValidity {
		return false, x509Cert, nil
	}
	if cert.CertDomain != "" {
		if err := x509Cert.VerifyHostname(cert.CertDomain); err != nil {
			return false, x509Cert, nil
		}
	}
	if !allowSelfSigned && isSelfSignedCertificate(x509Cert) {
		return false, x509Cert, nil
	}
	return true, x509Cert, nil
}

func loadCertificate(cert *conf.CertConfig) (*x509.Certificate, error) {
	data, err := os.ReadFile(cert.CertFile)
	if err != nil {
		return nil, fmt.Errorf("đọc cert file lỗi: %s", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode cert file lỗi: thiếu PEM block")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert file lỗi: %s", err)
	}
	return x509Cert, nil
}

func isSelfSignedCertificate(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func renewBefore(target string) time.Duration {
	if net.ParseIP(target) != nil {
		return ipRenewBefore
	}
	return domainRenewBefore
}

func validateAutoCertTarget(target string) error {
	if target == "" {
		return fmt.Errorf("auto tls cần host hoặc tls_settings.server_name")
	}
	if ip := net.ParseIP(target); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("auto tls target %s không phải IP public", target)
		}
		return nil
	}
	if strings.EqualFold(target, "localhost") || !strings.Contains(target, ".") {
		return fmt.Errorf("auto tls target %s không phải domain public", target)
	}
	if strings.ContainsAny(target, `/\\`) {
		return fmt.Errorf("auto tls target %s không phải hostname hợp lệ", target)
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}

func normalizeCertTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	return strings.TrimSpace(value)
}

func autoCertChallenge(cert *conf.CertConfig) (string, string) {
	if net.ParseIP(cert.CertDomain) != nil {
		return "http", "acme_ip"
	}
	if strings.TrimSpace(cert.Provider) != "" && len(cert.DNSEnv) > 0 {
		return "dns", "acme_dns"
	}
	return "http", "acme_http"
}

func managedCertSource(mode, target string) string {
	if mode == "dns" {
		return "acme_dns"
	}
	if net.ParseIP(target) != nil {
		return "acme_ip"
	}
	return "acme_http"
}

func metadataFromCertFile(cert *conf.CertConfig, source string) (*certMetadata, error) {
	x509Cert, err := loadCertificate(cert)
	if err != nil {
		return basicCertMetadata(cert, source), err
	}
	return metadataFromCertificate(cert, x509Cert, source), nil
}

func metadataFromCertificate(cert *conf.CertConfig, x509Cert *x509.Certificate, source string) *certMetadata {
	return &certMetadata{
		Target:    cert.CertDomain,
		Mode:      cert.CertMode,
		Source:    source,
		SHA256:    certSHA256(x509Cert),
		NotAfter:  x509Cert.NotAfter.Unix(),
		UpdatedAt: time.Now().Unix(),
	}
}

func basicCertMetadata(cert *conf.CertConfig, source string) *certMetadata {
	if cert == nil {
		return nil
	}
	return &certMetadata{
		Target:    cert.CertDomain,
		Mode:      cert.CertMode,
		Source:    source,
		UpdatedAt: time.Now().Unix(),
	}
}

func certSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (c *Controller) certMetadataPath() string {
	nodeID := 0
	if c.info != nil {
		nodeID = c.info.Id
	} else if c.apiClient != nil {
		nodeID = c.apiClient.NodeId
	}
	return filepath.Join("/etc/V2bZ", fmt.Sprintf("node-%d.certmeta.json", nodeID))
}

func (c *Controller) writeCertMetadata(meta *certMetadata) error {
	if meta == nil {
		return nil
	}
	if err := checkPath(c.certMetadataPath()); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.certMetadataPath(), data, 0644)
}

func (c *Controller) readCertMetadata() (*certMetadata, error) {
	data, err := os.ReadFile(c.certMetadataPath())
	if err != nil {
		return nil, err
	}
	var meta certMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func certMetadataChanged(previous, next *certMetadata) bool {
	if next == nil {
		return false
	}
	if previous == nil {
		return true
	}
	return previous.Target != next.Target ||
		previous.Mode != next.Mode ||
		previous.Source != next.Source ||
		previous.SHA256 != next.SHA256 ||
		previous.NotAfter != next.NotAfter
}

func (c *Controller) reportCertStatus(meta *certMetadata, issueErr error) {
	if c.apiClient == nil || meta == nil {
		return
	}
	status := "ok"
	errorMessage := ""
	if issueErr != nil {
		status = "error"
		errorMessage = issueErr.Error()
	}
	report := &panel.CertReport{
		Status:   status,
		Target:   meta.Target,
		Mode:     meta.Mode,
		Source:   meta.Source,
		SHA256:   meta.SHA256,
		NotAfter: meta.NotAfter,
		Error:    errorMessage,
	}
	if err := c.apiClient.ReportCertStatus(report); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Report cert status failed")
	}
}

func (c *Controller) reloadNodeAfterCertChange() {
	if c.server == nil || c.info == nil || c.activeOptions == nil {
		return
	}
	if err := c.server.DelNode(c.tag); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Delete node before cert reload failed")
		return
	}
	if err := c.server.AddNode(c.tag, c.info, c.activeOptions); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Add node after cert reload failed")
		return
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: c.info,
	})
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Add users after cert reload failed")
		return
	}
	log.WithField("tag", c.tag).Infof("Reloaded node after cert change, added %d users", added)
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := checkPath(certPath); err != nil {
		return err
	}
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return err
	}
	if err := checkPath(keyPath); err != nil {
		return err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
