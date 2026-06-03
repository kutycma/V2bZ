package cmd

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/kutycma/V2bZ/conf"
	vCore "github.com/kutycma/V2bZ/core"
	"github.com/kutycma/V2bZ/limiter"
	"github.com/kutycma/V2bZ/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Chạy server V2bZ",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/V2bZ/config.json", "đường dẫn file cấu hình")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "theo dõi thay đổi file cấu hình")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Tải file cấu hình thất bại")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Mở file log thất bại, dùng stdout thay thế")
		}
		log.SetOutput(f)
	}
	limiter.Init()
	log.Info("Đang khởi động V2bZ...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		log.WithField("err", err).Error("Tạo core thất bại")
		return
	}
	err = vc.Start()
	if err != nil {
		log.WithField("err", err).Error("Khởi động core thất bại")
		return
	}
	defer vc.Close()
	log.Info("Core ", vc.Type(), " đã khởi động")
	nodes := node.New()
	err = nodes.Start(c.NodeConfig, vc)
	if err != nil {
		log.WithField("err", err).Error("Chạy node thất bại")
		return
	}
	log.Info("Nodes đã khởi động")
	xdns := os.Getenv("XRAY_DNS_PATH")
	sdns := os.Getenv("SING_DNS_PATH")
	if watch {
		err = c.Watch(config, xdns, sdns, func() {
			nodes.Close()
			err = vc.Close()
			if err != nil {
				log.WithField("err", err).Error("Khởi động lại node thất bại")
				return
			}
			vc, err = vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("Tạo core mới thất bại")
				return
			}
			err = vc.Start()
			if err != nil {
				log.WithField("err", err).Error("Khởi động core thất bại")
				return
			}
			log.Info("Core ", vc.Type(), " đã khởi động lại")
			err = nodes.Start(c.NodeConfig, vc)
			if err != nil {
				log.WithField("err", err).Error("Chạy node thất bại")
				return
			}
			log.Info("Nodes đã khởi động lại")
			runtime.GC()
		})
		if err != nil {
			log.WithField("err", err).Error("Bắt đầu theo dõi file thất bại")
			return
		}
	}
	// clear memory
	runtime.GC()
	// wait exit signal
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
		<-osSignals
	}
}
