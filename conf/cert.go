package conf

type CertConfig struct {
	CertMode         string            `json:"CertMode"` // none, file, http, dns, auto, self
	RejectUnknownSni bool              `json:"RejectUnknownSni"`
	SelfFallback     bool              `json:"SelfFallback"`
	CertDomain       string            `json:"CertDomain"`
	CertFile         string            `json:"CertFile"`
	KeyFile          string            `json:"KeyFile"`
	Provider         string            `json:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email            string            `json:"Email"`
	DNSEnv           map[string]string `json:"DNSEnv"`
}

func NewCertConfig() *CertConfig {
	return &CertConfig{
		CertMode: "none",
	}
}
