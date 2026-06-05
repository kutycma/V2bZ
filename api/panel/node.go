package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kutycma/V2bZ/conf"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	RawDNS       RawDNS
	Rules        Rules

	// origin
	VAllss      *VAllssNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	Common      *CommonNode

	PanelCertConfig              *conf.CertConfig
	PanelCertSelfFallbackSet     bool
	PanelCertRejectUnknownSniSet bool
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	CommonNode
	Tls                 int             `json:"tls"`
	TlsSettings         TlsSettings     `json:"tls_settings"`
	TlsSettingsBack     *TlsSettings    `json:"tlsSettings"`
	Network             string          `json:"network"`
	NetworkSettings     json.RawMessage `json:"network_settings"`
	NetworkSettingsBack json.RawMessage `json:"networkSettings"`
	Encryption          string          `json:"encryption"`
	EncryptionSettings  EncSettings     `json:"encryption_settings"`
	ServerName          string          `json:"server_name"`

	// vless only
	Flow          string        `json:"flow"`
	RealityConfig RealityConfig `json:"-"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	ServerNames      []string `json:"server_names"`
	Dest             string   `json:"dest"`
	ServerPort       string   `json:"server_port"`
	ShortId          string   `json:"short_id"`
	ShortIds         []string `json:"short_ids"`
	PrivateKey       string   `json:"private_key"`
	Mldsa65Seed      string   `json:"mldsa65Seed"`
	Xver             uint64   `json:"xver,string"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	SelfFallback     bool     `json:"self_fallback"`
	RejectUnknownSni bool     `json:"reject_unknown_sni"`

	HasSelfFallback     bool `json:"-"`
	HasRejectUnknownSni bool `json:"-"`
	HasCertFields       bool `json:"-"`
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	CommonNode
	Network              string          `json:"network"`
	NetworkSettings      json.RawMessage `json:"networkSettings"`
	NetworkSettingsSnake json.RawMessage `json:"network_settings"`
	TlsSettings          TlsSettings     `json:"tls_settings"`
	TlsSettingsBack      *TlsSettings    `json:"tlsSettings"`
}

type TuicNode struct {
	CommonNode
	TlsSettings       TlsSettings  `json:"tls_settings"`
	TlsSettingsBack   *TlsSettings `json:"tlsSettings"`
	CongestionControl string       `json:"congestion_control"`
	ZeroRTTHandshake  bool         `json:"zero_rtt_handshake"`
}

type AnyTlsNode struct {
	CommonNode
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
	PaddingScheme   []string     `json:"padding_scheme,omitempty"`
}

type HysteriaNode struct {
	CommonNode
	TlsSettings     TlsSettings  `json:"tls_settings"`
	TlsSettingsBack *TlsSettings `json:"tlsSettings"`
	UpMbps          int          `json:"up_mbps"`
	DownMbps        int          `json:"down_mbps"`
	Obfs            string       `json:"obfs"`
}

type Hysteria2Node struct {
	CommonNode
	TlsSettings             TlsSettings  `json:"tls_settings"`
	TlsSettingsBack         *TlsSettings `json:"tlsSettings"`
	Ignore_Client_Bandwidth bool         `json:"ignore_client_bandwidth"`
	UpMbps                  int          `json:"up_mbps"`
	DownMbps                int          `json:"down_mbps"`
	ObfsType                string       `json:"obfs"`
	ObfsPassword            string       `json:"obfs-password"`
}

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

type Rules struct {
	Regexp   []string
	Protocol []string
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/api/v3/server/UniProxy/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, c.checkResponse(r, path, err)
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	if r.RawBody() != nil {
		defer r.RawBody().Close()
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch c.NodeType {
	case "vmess", "vless":
		rsp := &VAllssNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode v2ray params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		rsp.NetworkSettings = normalizeRawJSON(rsp.NetworkSettings)
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.VAllss = rsp
		node.Security = node.VAllss.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trojan params error: %s", err)
		}
		if len(rsp.NetworkSettings) == 0 && len(rsp.NetworkSettingsSnake) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsSnake
		}
		rsp.NetworkSettings = normalizeRawJSON(rsp.NetworkSettings)
		rsp.NetworkSettingsSnake = nil
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = Tls
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode tuic params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode anytls params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		node.Security = Tls
	case "hysteria":
		rsp := &HysteriaNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Hysteria = rsp
		node.Security = Tls
	case "hysteria2":
		rsp := &Hysteria2Node{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria2 params error: %s", err)
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.Hysteria2 = rsp
		node.Security = Tls
	}
	if cm == nil {
		return nil, fmt.Errorf("UniProxy trả về node_type chưa được V2bZ hỗ trợ: %s", c.NodeType)
	}

	// parse rules and dns
	for i := range cm.Routes {
		matchs := routeMatchesToStrings(cm.Routes[i].Match)
		if len(matchs) == 0 {
			continue
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					// protocol
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					// domain
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		}
	}

	// set interval
	node.PushInterval = time.Minute
	node.PullInterval = time.Minute
	if cm.BaseConfig != nil {
		node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
		node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)
	}

	node.Common = cm
	node.PanelCertConfig, node.PanelCertSelfFallbackSet, node.PanelCertRejectUnknownSniSet = buildPanelCertConfig(c.NodeId, node, cm)
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil

	return node, nil
}

func intervalToTime(i interface{}) time.Duration {
	if i == nil {
		return time.Minute
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}

func (t *TlsSettings) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]")) {
		*t = TlsSettings{}
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}

	*t = TlsSettings{
		ServerName:       mapString(raw, "server_name", "serverName"),
		ServerNames:      mapStringSlice(raw, "server_names", "serverNames"),
		Dest:             mapString(raw, "dest"),
		ServerPort:       mapString(raw, "server_port", "serverPort"),
		ShortId:          mapString(raw, "short_id", "shortId"),
		ShortIds:         mapStringSlice(raw, "short_ids", "shortIds"),
		PrivateKey:       mapString(raw, "private_key", "privateKey"),
		Mldsa65Seed:      mapString(raw, "mldsa65Seed", "mldsa65_seed"),
		Xver:             mapUint64(raw, "xver"),
		CertMode:         mapString(raw, "cert_mode", "certMode", "CertMode"),
		CertFile:         mapString(raw, "cert_file", "certFile", "CertFile"),
		KeyFile:          mapString(raw, "key_file", "keyFile", "KeyFile"),
		Provider:         mapString(raw, "provider", "Provider"),
		DNSEnv:           mapDNSEnv(raw, "dns_env", "dnsEnv", "DNSEnv"),
		SelfFallback:     mapBool(raw, "self_fallback", "selfFallback", "SelfFallback"),
		RejectUnknownSni: mapBool(raw, "reject_unknown_sni", "rejectUnknownSni", "RejectUnknownSni"),
	}
	t.HasSelfFallback = mapHas(raw, "self_fallback", "selfFallback", "SelfFallback")
	t.HasRejectUnknownSni = mapHas(raw, "reject_unknown_sni", "rejectUnknownSni", "RejectUnknownSni")
	t.HasCertFields = mapHas(raw,
		"cert_mode", "certMode", "CertMode",
		"cert_file", "certFile", "CertFile",
		"key_file", "keyFile", "KeyFile",
		"provider", "Provider",
		"dns_env", "dnsEnv", "DNSEnv",
		"self_fallback", "selfFallback", "SelfFallback",
		"reject_unknown_sni", "rejectUnknownSni", "RejectUnknownSni",
	)
	return nil
}

func mapHas(raw map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}

func mapValue(raw map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			return value
		}
	}
	return nil
}

func mapString(raw map[string]interface{}, keys ...string) string {
	value := mapValue(raw, keys...)
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
}

func mapStringSlice(raw map[string]interface{}, keys ...string) []string {
	value := mapValue(raw, keys...)
	switch v := value.(type) {
	case nil:
		return nil
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			text := strings.TrimSpace(mapAnyString(item))
			if text != "" {
				items = append(items, text)
			}
		}
		return items
	case []string:
		return v
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return nil
		}
		if strings.HasPrefix(text, "[") {
			var decoded []interface{}
			if err := json.Unmarshal([]byte(text), &decoded); err == nil {
				return mapStringSlice(map[string]interface{}{"value": decoded}, "value")
			}
		}
		return []string{text}
	default:
		text := strings.TrimSpace(mapAnyString(v))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func mapAnyString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		data, _ := json.Marshal(v)
		return string(data)
	}
}

func mapBool(raw map[string]interface{}, keys ...string) bool {
	value := mapValue(raw, keys...)
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y", "on":
			return true
		default:
			return false
		}
	case float64:
		return v != 0
	default:
		return false
	}
}

func mapUint64(raw map[string]interface{}, keys ...string) uint64 {
	value := mapValue(raw, keys...)
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return uint64(v)
		}
	case string:
		parsed, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return parsed
	}
	return 0
}

func mapDNSEnv(raw map[string]interface{}, keys ...string) string {
	value := mapValue(raw, keys...)
	if value == nil {
		return ""
	}
	if env, ok := value.(map[string]interface{}); ok {
		items := make([]string, 0, len(env))
		for k, v := range env {
			key := strings.TrimSpace(k)
			if key != "" {
				items = append(items, key+"="+mapAnyString(v))
			}
		}
		return strings.Join(items, ",")
	}
	return mapString(map[string]interface{}{"value": value}, "value")
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

func (t TlsSettings) PrimaryServerName() string {
	serverNames := t.EffectiveServerNames()
	if len(serverNames) == 0 {
		return ""
	}
	return serverNames[0]
}

func nodeTlsSettings(node *NodeInfo) TlsSettings {
	if node == nil {
		return TlsSettings{}
	}
	switch node.Type {
	case "vmess", "vless":
		if node.VAllss != nil {
			return node.VAllss.TlsSettings
		}
	case "trojan":
		if node.Trojan != nil {
			return node.Trojan.TlsSettings
		}
	case "tuic":
		if node.Tuic != nil {
			return node.Tuic.TlsSettings
		}
	case "anytls":
		if node.AnyTls != nil {
			return node.AnyTls.TlsSettings
		}
	case "hysteria":
		if node.Hysteria != nil {
			return node.Hysteria.TlsSettings
		}
	case "hysteria2":
		if node.Hysteria2 != nil {
			return node.Hysteria2.TlsSettings
		}
	}
	return TlsSettings{}
}

func buildPanelCertConfig(nodeID int, node *NodeInfo, cm *CommonNode) (*conf.CertConfig, bool, bool) {
	tls := nodeTlsSettings(node)
	if !tls.HasCertFields {
		return nil, false, false
	}
	certDomain := strings.TrimSpace(tls.PrimaryServerName())
	if certDomain == "" && cm != nil {
		certDomain = strings.TrimSpace(cm.ServerName)
	}
	if certDomain == "" && cm != nil {
		certDomain = strings.TrimSpace(cm.Host)
	}
	certFile := strings.TrimSpace(tls.CertFile)
	if certFile == "" {
		certFile = filepath.Join("/etc/V2bZ", "node-"+strconv.Itoa(nodeID)+".cer")
	}
	keyFile := strings.TrimSpace(tls.KeyFile)
	if keyFile == "" {
		keyFile = filepath.Join("/etc/V2bZ", "node-"+strconv.Itoa(nodeID)+".key")
	}

	return &conf.CertConfig{
		CertMode:         strings.TrimSpace(tls.CertMode),
		CertFile:         certFile,
		KeyFile:          keyFile,
		Email:            "node@zicboard.local",
		CertDomain:       certDomain,
		DNSEnv:           parseDNSEnv(tls.DNSEnv),
		Provider:         strings.TrimSpace(tls.Provider),
		SelfFallback:     tls.SelfFallback,
		RejectUnknownSni: tls.RejectUnknownSni,
	}, tls.HasSelfFallback, tls.HasRejectUnknownSni
}

func parseDNSEnv(value string) map[string]string {
	result := make(map[string]string)
	value = strings.TrimSpace(value)
	if value == "" {
		return result
	}
	if strings.HasPrefix(value, "{") {
		var decoded map[string]string
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			for k, v := range decoded {
				key := strings.TrimSpace(k)
				if key != "" {
					result[key] = v
				}
			}
			return result
		}
	}
	envs := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	for _, env := range envs {
		kv := strings.SplitN(env, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		if key != "" {
			result[key] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

func normalizeRawJSON(value json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if bytes.Equal(trimmed, []byte("[]")) {
		return json.RawMessage(`{}`)
	}
	return trimmed
}

func routeMatchesToStrings(match interface{}) []string {
	switch value := match.(type) {
	case nil:
		return nil
	case string:
		if value == "" {
			return nil
		}
		return strings.Split(value, ",")
	case []string:
		return value
	case []interface{}:
		matches := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				matches = append(matches, text)
			}
		}
		return matches
	default:
		return nil
	}
}
