package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "TempVersion" //thay bằng ldflags
	codename = "V2bZ"
	intro    = "Backend V2board dựa trên nhiều core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "In thông tin phiên bản",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

func showVersion() {
	fmt.Println(` 
  _/      _/    _/_/    _/        _/      _/   
 _/      _/  _/    _/  _/_/_/      _/  _/      
_/      _/      _/    _/    _/      _/         
 _/  _/      _/      _/    _/    _/  _/        
  _/      _/_/_/_/  _/_/_/    _/      _/        
                                                `)
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
	//fmt.Printf("Core được hỗ trợ: %s\n", strings.Join(vCore.RegisteredCore(), ", "))
	// Warning
	//fmt.Println(Warn("Phiên bản này cần V2board >= 1.7.0."))
	//fmt.Println(Warn("Phiên bản này có nhiều thay đổi cấu hình, vui lòng kiểm tra file cấu hình"))
}
