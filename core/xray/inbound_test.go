package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kutycma/V2bZ/api/panel"
	"github.com/kutycma/V2bZ/conf"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildV2rayMapsHTTPAndIgnoresNullSettings(t *testing.T) {
	inbound := &coreConf.InboundDetourConfig{}
	node := &panel.NodeInfo{
		Type: "vmess",
		VAllss: &panel.VAllssNode{
			Network:         "http",
			NetworkSettings: json.RawMessage("null"),
		},
	}

	if err := buildV2ray(&conf.Options{XrayOptions: conf.NewXrayOptions()}, node, inbound); err != nil {
		t.Fatalf("build v2ray: %v", err)
	}
	if node.VAllss.Network != "httpupgrade" {
		t.Fatalf("expected http to map to httpupgrade, got %q", node.VAllss.Network)
	}
	if inbound.StreamSetting == nil || inbound.StreamSetting.Network == nil {
		t.Fatalf("expected stream setting network to be set")
	}
	if got := string(*inbound.StreamSetting.Network); got != "httpupgrade" {
		t.Fatalf("unexpected stream network: %s", got)
	}
}

func TestBuildV2rayRejectsUnsupportedNetworkWithoutSettings(t *testing.T) {
	inbound := &coreConf.InboundDetourConfig{}
	node := &panel.NodeInfo{
		Type: "vless",
		VAllss: &panel.VAllssNode{
			Network:         "quic",
			NetworkSettings: json.RawMessage("null"),
		},
	}

	err := buildV2ray(&conf.Options{XrayOptions: conf.NewXrayOptions()}, node, inbound)
	if err == nil || !strings.Contains(err.Error(), "chưa được V2bZ xray hỗ trợ") {
		t.Fatalf("expected unsupported network error, got %v", err)
	}
}

func TestBuildTrojanRejectsUnsupportedNetwork(t *testing.T) {
	inbound := &coreConf.InboundDetourConfig{}
	node := &panel.NodeInfo{
		Trojan: &panel.TrojanNode{Network: "http"},
	}

	err := buildTrojan(&conf.Options{XrayOptions: conf.NewXrayOptions()}, node, inbound)
	if err == nil || !strings.Contains(err.Error(), "hãy dùng tcp/ws/grpc") {
		t.Fatalf("expected trojan network error, got %v", err)
	}
}
