package aes256ofb

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	mustWork := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	testFile := "aes256ofb_test.go" // this file
	c := Client{
		AESKey: NewAESKey(),
		IV:     NewIV(),
		Logger: DefaultLogger,
		FileFilter: func(name string) bool {
			return name == testFile
		},
	}
	var encrypted bytes.Buffer
	md5sum := md5.New()
	mustWork(c.Encrypt(io.MultiWriter(&encrypted, md5sum)).FromDirectory("./"))
	t.Log("encrypted file base64:", base64.StdEncoding.EncodeToString(encrypted.Bytes()))
	t.Logf("encrypted file md5: %02X", md5sum.Sum(nil))
	cmd := c.OpensslDecryptCommand()
	t.Log("running openssl:", cmd)
	openssl := exec.Command(cmd[0], cmd[1:]...)
	pigz := exec.Command("pigz", "-cdz", "-")         // zlib decompress
	tar := exec.Command("tar", "-Oxf", "-", testFile) // show only test file content

	pigzR, opensslW := io.Pipe()
	openssl.Stdin = &encrypted
	openssl.Stdout = opensslW
	pigz.Stdin = pigzR

	var decrypted bytes.Buffer
	tarR, pigzW := io.Pipe()
	tar.Stdin = tarR
	tar.Stdout = &decrypted
	pigz.Stdout = pigzW

	mustWork(openssl.Start())
	mustWork(pigz.Start())
	mustWork(tar.Start())
	mustWork(openssl.Wait())
	mustWork(opensslW.Close())
	mustWork(pigz.Wait())
	mustWork(pigzW.Close())
	mustWork(tar.Wait())

	expected, err := ioutil.ReadFile(testFile)
	mustWork(err)
	if bytes.Equal(decrypted.Bytes(), expected) {
		t.Log("OK! The encrypted file can be decrypted by openssl!")
	} else {
		t.Error("file not match")
	}
}

func TestEmpty(t *testing.T) {
	c := Client{
		AESKey: NewAESKey(),
		IV:     NewIV(),
		FileFilter: func(name string) bool {
			return name == "NoSuchFile"
		},
	}
	var encrypted bytes.Buffer
	err := c.Encrypt(&encrypted).FromDirectory("./")
	if err != ErrNoFiles {
		t.Error("should be ErrNoFiles")
	}
}

func TestBadCompressionLevel(t *testing.T) {
	c := Client{
		AESKey: NewAESKey(),
		IV:     NewIV(),
	}
	var encrypted bytes.Buffer
	err := c.Encrypt(&encrypted).WithCompressionLevel(100).FromDirectory("./")
	if err == nil || !strings.Contains(err.Error(), "invalid compression level") {
		t.Error("should be invalid compression level error")
	}
}
