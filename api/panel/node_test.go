package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kutycma/V2bZ/conf"
)

func newTestClient(t *testing.T, nodeType string, body string) (*Client, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/server/UniProxy/config" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("node_type"); got != nodeType {
			http.Error(w, fmt.Sprintf("unexpected node_type %s", got), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))

	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		Key:      "token",
		NodeType: nodeType,
		NodeID:   12,
	})
	if err != nil {
		server.Close()
		t.Fatalf("new panel client: %v", err)
	}

	return client, server.Close
}

func TestNewRejectsZicnodeForUniProxy(t *testing.T) {
	_, err := New(&conf.ApiConfig{NodeType: "zicnode"})
	if err == nil || !strings.Contains(err.Error(), "UniProxy") {
		t.Fatalf("expected UniProxy zicnode error, got %v", err)
	}
}

func TestClientGetNodeInfoAcceptsVlessCamelCase(t *testing.T) {
	client, closeServer := newTestClient(t, "vless", `{
		"server_port": 443,
		"network": "http",
		"networkSettings": null,
		"tls": 0,
		"base_config": {"push_interval": 30, "pull_interval": "45"},
		"routes": [{"match": ["protocol:bittorrent", "regexp:example.com"], "action": "block"}]
	}`)
	defer closeServer()

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info: %v", err)
	}
	if node.Type != "vless" || node.VAllss == nil {
		t.Fatalf("unexpected node type: %+v", node)
	}
	if len(node.VAllss.NetworkSettings) != 0 {
		t.Fatalf("expected null network settings to be ignored, got %q", node.VAllss.NetworkSettings)
	}
	if node.PushInterval != 30*time.Second || node.PullInterval != 45*time.Second {
		t.Fatalf("unexpected intervals: push=%s pull=%s", node.PushInterval, node.PullInterval)
	}
	if len(node.Rules.Protocol) != 1 || node.Rules.Protocol[0] != "bittorrent" {
		t.Fatalf("unexpected protocol rules: %+v", node.Rules.Protocol)
	}
	if len(node.Rules.Regexp) != 1 || node.Rules.Regexp[0] != "example.com" {
		t.Fatalf("unexpected regexp rules: %+v", node.Rules.Regexp)
	}
}

func TestClientGetNodeInfoAcceptsTrojanSnakeCase(t *testing.T) {
	client, closeServer := newTestClient(t, "trojan", `{
		"server_port": 443,
		"network": "ws",
		"network_settings": {"path":"/trojan"},
		"base_config": {"push_interval": 60, "pull_interval": 60}
	}`)
	defer closeServer()

	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("get node info: %v", err)
	}
	if node.Type != "trojan" || node.Trojan == nil {
		t.Fatalf("unexpected node type: %+v", node)
	}
	if !strings.Contains(string(node.Trojan.NetworkSettings), "/trojan") {
		t.Fatalf("expected snake_case network_settings to be preserved, got %q", node.Trojan.NetworkSettings)
	}
}
