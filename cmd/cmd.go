package cmd

import (
	log "github.com/sirupsen/logrus"

	_ "github.com/kutycma/V2bZ/core/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "V2bZ",
}

func Run() {
	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}
