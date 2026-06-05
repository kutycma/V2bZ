package conf

import (
	"testing"
)

func TestConf_LoadFromPath(t *testing.T) {
	c := New()
	t.Log(c.LoadFromPath("../example/config.json"), c.NodeConfig)
}

func TestConf_Watch(t *testing.T) {
	t.Skip("file watcher test requires a long-running external event loop")

	c := New()
	t.Log(c.Watch("./1.json", "", "", func() {}))
	select {}
}
