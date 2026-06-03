package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/kutycma/V2bZ/common/exec"
	"github.com/spf13/cobra"
)

var targetVersion string

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Cập nhật phiên bản V2bZ",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("bash",
				"<(curl -Ls https://raw.githubusercontent.com/kutycma/V2bZ-script/master/install.sh)",
				targetVersion)
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Gỡ cài đặt V2bZ",
		Run:   uninstallHandle,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "phiên bản cần cập nhật")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
}

func uninstallHandle(_ *cobra.Command, _ []string) {
	var yes string
	fmt.Println(Warn("Bạn chắc chắn muốn gỡ cài đặt V2bZ? (Y/n)"))
	fmt.Scan(&yes)
	if strings.ToLower(yes) != "y" {
		fmt.Println("Đã huỷ gỡ cài đặt")
	}
	_, err := exec.RunCommandByShell("systemctl stop V2bZ&&systemctl disable V2bZ")
	if err != nil {
		fmt.Println(Err("lỗi chạy lệnh: ", err))
		fmt.Println(Err("Gỡ cài đặt thất bại"))
		return
	}
	_ = os.RemoveAll("/etc/systemd/system/V2bZ.service")
	_ = os.RemoveAll("/etc/V2bZ/")
	_ = os.RemoveAll("/usr/local/V2bZ/")
	_ = os.RemoveAll("/bin/V2bZ")
	_, err = exec.RunCommandByShell("systemctl daemon-reload&&systemctl reset-failed")
	if err != nil {
		fmt.Println(Err("lỗi chạy lệnh: ", err))
		fmt.Println(Err("Gỡ cài đặt thất bại"))
		return
	}
	fmt.Println(Ok("Gỡ cài đặt thành công"))
}
