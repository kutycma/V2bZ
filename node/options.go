package node

import (
	"strings"

	"github.com/kutycma/V2bZ/api/panel"
	"github.com/kutycma/V2bZ/conf"
)

func (c *Controller) optionsForNode(node *panel.NodeInfo) *conf.Options {
	option := cloneOptions(c.Options)
	option.CertConfig = c.effectiveCertConfig(node)
	return option
}

func (c *Controller) effectiveCertConfig(node *panel.NodeInfo) *conf.CertConfig {
	cert := cloneCertConfig(c.CertConfig)
	if cert == nil {
		cert = conf.NewCertConfig()
	}
	if node == nil || node.PanelCertConfig == nil {
		return cert
	}

	panelCert := node.PanelCertConfig
	panelMode := strings.TrimSpace(panelCert.CertMode)
	if panelMode != "" {
		cert.CertMode = panelMode
		cert.CertDomain = strings.TrimSpace(panelCert.CertDomain)
		cert.CertFile = strings.TrimSpace(panelCert.CertFile)
		cert.KeyFile = strings.TrimSpace(panelCert.KeyFile)
		cert.Email = strings.TrimSpace(panelCert.Email)
		cert.Provider = strings.TrimSpace(panelCert.Provider)
		cert.DNSEnv = cloneDNSEnv(panelCert.DNSEnv)
	}

	if node.PanelCertSelfFallbackSet {
		cert.SelfFallback = panelCert.SelfFallback
	}
	if node.PanelCertRejectUnknownSniSet {
		cert.RejectUnknownSni = panelCert.RejectUnknownSni
	}

	return cert
}

func cloneOptions(option *conf.Options) *conf.Options {
	if option == nil {
		return &conf.Options{CertConfig: conf.NewCertConfig()}
	}
	clone := *option
	clone.CertConfig = cloneCertConfig(option.CertConfig)
	return &clone
}

func cloneCertConfig(cert *conf.CertConfig) *conf.CertConfig {
	if cert == nil {
		return nil
	}
	clone := *cert
	clone.DNSEnv = cloneDNSEnv(cert.DNSEnv)
	return &clone
}

func cloneDNSEnv(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	clone := make(map[string]string, len(env))
	for k, v := range env {
		clone[k] = v
	}
	return clone
}
