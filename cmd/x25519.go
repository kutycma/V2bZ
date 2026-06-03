package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kutycma/V2bZ/common/crypt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/curve25519"
)

var x25519Command = cobra.Command{
	Use:   "x25519",
	Short: "Tạo cặp khoá trao đổi x25519",
	Run: func(cmd *cobra.Command, args []string) {
		executeX25519()
	},
}

func init() {
	command.AddCommand(&x25519Command)
}

func executeX25519() {
	var output string
	var err error
	defer func() {
		fmt.Println(output)
	}()
	var privateKey []byte
	var publicKey []byte
	var yes, key string
	fmt.Println("Tạo khoá dựa trên thông tin node? (Y/n)")
	fmt.Scan(&yes)
	if strings.ToLower(yes) == "y" {
		var temp string
		fmt.Println("Nhập node id:")
		fmt.Scan(&temp)
		key = temp
		fmt.Println("Nhập loại node:")
		fmt.Scan(&temp)
		key += strings.ToLower(temp)
		fmt.Println("Nhập token:")
		fmt.Scan(&temp)
		key += temp
		privateKey = crypt.GenX25519Private([]byte(key))
	} else {
		privateKey = make([]byte, curve25519.ScalarSize)
		if _, err = rand.Read(privateKey); err != nil {
			output = Err("lỗi đọc random: ", err)
			return
		}
	}
	if publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint); err != nil {
		output = Err("lỗi tạo X25519: ", err)
		return
	}
	p := base64.RawURLEncoding.EncodeToString(privateKey)
	output = fmt.Sprint("Khoá riêng: ",
		p,
		"\nKhoá công khai: ",
		base64.RawURLEncoding.EncodeToString(publicKey))
}
