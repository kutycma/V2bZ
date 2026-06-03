package cmd

import (
	"fmt"
	"time"

	"github.com/kutycma/V2bZ/common/exec"
	"github.com/spf13/cobra"
)

var (
	startCommand = cobra.Command{
		Use:   "start",
		Short: "Khởi động dịch vụ V2bZ",
		Run:   startHandle,
	}
	stopCommand = cobra.Command{
		Use:   "stop",
		Short: "Dừng dịch vụ V2bZ",
		Run:   stopHandle,
	}
	restartCommand = cobra.Command{
		Use:   "restart",
		Short: "Khởi động lại dịch vụ V2bZ",
		Run:   restartHandle,
	}
	logCommand = cobra.Command{
		Use:   "log",
		Short: "Xem log V2bZ",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("journalctl", "-u", "V2bZ.service", "-e", "--no-pager", "-f")
		},
	}
)

func init() {
	command.AddCommand(&startCommand)
	command.AddCommand(&stopCommand)
	command.AddCommand(&restartCommand)
	command.AddCommand(&logCommand)
}

func startHandle(_ *cobra.Command, _ []string) {
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("lỗi kiểm tra trạng thái: ", err))
		fmt.Println(Err("V2bZ khởi động thất bại"))
		return
	}
	if r {
		fmt.Println(Ok("V2bZ đang chạy, không cần khởi động lại. Nếu cần, hãy chọn restart"))
	}
	_, err = exec.RunCommandByShell("systemctl start V2bZ.service")
	if err != nil {
		fmt.Println(Err("lỗi chạy lệnh khởi động: ", err))
		fmt.Println(Err("V2bZ khởi động thất bại"))
		return
	}
	time.Sleep(time.Second * 3)
	r, err = checkRunning()
	if err != nil {
		fmt.Println(Err("lỗi kiểm tra trạng thái: ", err))
		fmt.Println(Err("V2bZ khởi động thất bại"))
	}
	if !r {
		fmt.Println(Err("V2bZ có thể khởi động thất bại. Vui lòng dùng V2bZ log để xem log sau"))
		return
	}
	fmt.Println(Ok("V2bZ khởi động thành công. Dùng V2bZ log để xem log chạy"))
}

func stopHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl stop V2bZ.service")
	if err != nil {
		fmt.Println(Err("lỗi chạy lệnh dừng: ", err))
		fmt.Println(Err("Dừng V2bZ thất bại"))
		return
	}
	time.Sleep(2 * time.Second)
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error:", err))
		fmt.Println(Err("Dừng V2bZ thất bại"))
		return
	}
	if r {
		fmt.Println(Err("Dừng V2bZ thất bại, có thể do quá thời gian 2 giây. Vui lòng xem log sau"))
		return
	}
	fmt.Println(Ok("V2bZ dừng thành công"))
}

func restartHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl restart V2bZ.service")
	if err != nil {
		fmt.Println(Err("lỗi chạy lệnh khởi động lại: ", err))
		fmt.Println(Err("V2bZ khởi động lại thất bại"))
		return
	}
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("lỗi kiểm tra trạng thái: ", err))
		fmt.Println(Err("V2bZ khởi động lại thất bại"))
		return
	}
	if !r {
		fmt.Println(Err("V2bZ có thể khởi động thất bại. Vui lòng dùng V2bZ log để xem log sau"))
		return
	}
	fmt.Println(Ok("V2bZ khởi động lại thành công"))
}
