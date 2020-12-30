package aes256ofb

import (
	"archive/tar"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

type (
	AESKey []byte

	Client struct {
		AESKey     AESKey
		IV         []byte
		FileFilter func(string) bool
		Logger     func(bool, bool, string, int64)

		writer io.Writer
		reader io.Reader

		zlibWriterLevel *int
	}
)

var (
	ErrNoFiles = errors.New("no files")
)

// generate random AES key
func NewAESKey() AESKey {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// AES key to Go code
func (key AESKey) String() string {
	out := `var AES_KEY = strings.Join([]string{`
	for i, b := range key {
		if i%8 == 0 {
			out += "\n\t"
		} else {
			out += " "
		}
		out += fmt.Sprintf(`"\x%02X",`, b)
	}
	out += "\n"
	out += `}, "")`
	return out
}

// generate random IV
func NewIV() []byte {
	b := make([]byte, aes.BlockSize)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// default logger for encryption and decryption
func DefaultLogger(compress, dir bool, name string, size int64) {
	if compress {
		if dir {
			log.Printf("adding dir  %-40s\n", name)
		} else {
			log.Printf("adding file %-40s %8d bytes\n", name, size)
		}
	} else {
		if dir {
			log.Printf("extracting dir  %-36s\n", name)
		} else {
			log.Printf("extracting file %-36s %8d bytes\n", name, size)
		}
	}
}

// set writer for encryption
func (c *Client) Encrypt(target io.Writer) *Client {
	c.writer = target
	return c
}

// set compression level
func (c *Client) WithCompressionLevel(compressionLevel int) *Client {
	c.zlibWriterLevel = &compressionLevel
	return c
}

// start encryption for directory
func (c *Client) FromDirectory(targetDir string) error {
	if c.writer == nil {
		return errors.New("no target")
	}
	block, err := aes.NewCipher(c.AESKey)
	if err != nil {
		return err
	}
	if len(c.IV) == 0 {
		c.IV = make([]byte, aes.BlockSize)
	}
	cipherW := &cipher.StreamWriter{
		S: cipher.NewOFB(block, c.IV),
		W: c.writer,
	}
	lvl := zlib.DefaultCompression
	if c.zlibWriterLevel != nil {
		lvl = *c.zlibWriterLevel
	}
	gzipW, err := zlib.NewWriterLevel(cipherW, lvl)
	if err != nil {
		return err
	}
	tarW := tar.NewWriter(gzipW)
	noFiles := true
	if err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(targetDir, path)
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if c.FileFilter != nil && !c.FileFilter(name) {
			return nil
		}
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(name)
		if err := tarW.WriteHeader(header); err != nil {
			return err
		}
		noFiles = false
		if info.IsDir() {
			if c.Logger != nil {
				c.Logger(true, true, header.Name, 0)
			}
		} else if info.Mode().IsRegular() {
			data, err := os.Open(path)
			if err != nil {
				return err
			}
			defer data.Close()
			if _, err := io.Copy(tarW, data); err != nil {
				return err
			}
			if c.Logger != nil {
				c.Logger(true, false, header.Name, info.Size())
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := tarW.Close(); err != nil {
		return err
	}
	if err := gzipW.Close(); err != nil {
		return err
	}
	if err := cipherW.Close(); err != nil {
		return err
	}
	if noFiles {
		return ErrNoFiles
	}
	return nil
}

// set reader for decryption
func (c *Client) Decrypt(source io.Reader) *Client {
	c.reader = source
	return c
}

// print openssl decryption command
func (c *Client) OpensslDecryptCommand() []string {
	iv := hex.EncodeToString(c.IV)
	if iv == "" {
		iv = "0"
	}
	return []string{"openssl", "enc", "-d", "-aes-256-ofb", "-iv", iv, "-K", hex.EncodeToString(c.AESKey)}
}

// start decryption to directory
func (c *Client) ToDirectory(targetDir string) error {
	if c.reader == nil {
		return errors.New("no source")
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	block, err := aes.NewCipher(c.AESKey)
	if err != nil {
		return err
	}
	if len(c.IV) == 0 {
		c.IV = make([]byte, aes.BlockSize)
	}
	cipherR := &cipher.StreamReader{
		S: cipher.NewOFB(block, c.IV),
		R: c.reader,
	}
	gzipR, err := zlib.NewReader(cipherR)
	if err != nil {
		return err
	}
	tarR := tar.NewReader(gzipR)
tarFor:
	for {
		header, err := tarR.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		target := filepath.Join(targetDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			if c.Logger != nil {
				c.Logger(false, true, target, 0)
			}
		case tar.TypeReg:
			if c.FileFilter != nil && !c.FileFilter(header.Name) {
				continue tarFor
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			var n int64
			n, err = io.Copy(file, tarR)
			file.Close()
			if err != nil {
				return err
			}
			if c.Logger != nil {
				c.Logger(false, false, target, n)
			}
		}
	}
	return nil
}
