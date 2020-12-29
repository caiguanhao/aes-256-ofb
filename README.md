# aes256ofb

Encrypt and decrypt a directory (recursively) using aes-256-ofb

Usage:

```golang
package main

import (
	"bytes"
	"fmt"

	"github.com/caiguanhao/aes256ofb"
)

func main() {
	// f, err := os.OpenFile("dist.tar.gz.enc", os.O_RDWR|os.O_CREATE, 0755)
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()
	var f bytes.Buffer
	c := aes256ofb.Client{
		AESKey: aes256ofb.NewAESKey(),
		IV:     aes256ofb.NewIV(),
		Logger: aes256ofb.DefaultLogger,
		FileFilter: func(name string) bool {
			return name == "main.go"
		},
	}
	err := c.Encrypt(&f).FromDirectory("./")
	if err != nil {
		panic(err)
	}
	fmt.Println(c.OpensslDecryptCommand())
	err = c.Decrypt(&f).ToDirectory("./new")
	if err != nil {
		panic(err)
	}
	// 2020/12/29 16:12:55 adding file main.go                                       869 bytes
	// [openssl enc -d -aes-256-ofb -iv ... -K ...]
	// 2020/12/29 16:12:55 extracting file new/main.go                               869 bytes
}
```
