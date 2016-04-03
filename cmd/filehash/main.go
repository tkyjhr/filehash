package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
	"github.com/tkyjhr/go-filehash"
)

func hashPrintCommand(name string, aliases []string, hashFunc func(file string) []byte) cli.Command {
	return cli.Command{
		Name:    name,
		Aliases: aliases,
		Action: func(c *cli.Context) {
			files := c.Args()
			for _, f := range files {
				h := hashFunc(f)
				fmt.Printf("%x\n", h)
			}
		},
		Usage:     fmt.Sprintf("Print %s value(s) of [FILE]...", name),
		ArgsUsage: "[FILE]...",
	}
}

func main() {

	app := cli.NewApp()
	app.Name = "filehash"
	app.Usage = "Print hash value(s) of [FILE]..."
	app.ArgsUsage = "[FILE]..."
	app.UsageText = "filehash [COMMAND] [FILE]..."

	commands := []cli.Command{
		hashPrintCommand("SHA1", []string{"sha1", "s1"}, filehash.SHA1),
		hashPrintCommand("SHA256", []string{"sha256"}, filehash.SHA256),
		hashPrintCommand("SHA256-224", []string{"sha256-224"}, filehash.SHA224),
		hashPrintCommand("SHA512", []string{"sha512"}, filehash.SHA512),
		hashPrintCommand("SHA512-224", []string{"sha512"}, filehash.SHA512_224),
		hashPrintCommand("SHA512-256", []string{"sha512"}, filehash.SHA512_256),
		hashPrintCommand("SHA3-224", []string{"sha3-224", "s3-224"}, filehash.SHA3_224),
		hashPrintCommand("SHA3-256", []string{"sha3-256", "s3-256"}, filehash.SHA3_256),
		hashPrintCommand("SHA3-384", []string{"sha3-384", "s3-384"}, filehash.SHA3_384),
		hashPrintCommand("SHA3-512", []string{"sha3-512", "s3-512", "s3"}, filehash.SHA3_512),
		hashPrintCommand("MD5", []string{"md5", "m5"}, filehash.MD5),
		hashPrintCommand("CRC32-IEEE", []string{"crc32-ieee", "crc32", "c32"}, filehash.CRC32_IEEE),
		hashPrintCommand("CRC64-ISO", []string{"crc64-iso"}, filehash.CRC64_ISO),
		hashPrintCommand("CRC64-ECMA", []string{"crc64-ecma"}, filehash.CRC64_ECMA),
		hashPrintCommand("Adler-32", []string{"adler-32", "adler", "adl"}, filehash.Adler32),
		hashPrintCommand("FNV-32", []string{"fnv-32"}, filehash.FNV32),
		hashPrintCommand("FNV-32a", []string{"fnv-32a"}, filehash.FNV32a),
		hashPrintCommand("FNV-64", []string{"fnv-64"}, filehash.FNV64),
		hashPrintCommand("FNV-64a", []string{"fnv-64a"}, filehash.FNV64a),
	}

	app.Commands = commands

	app.Run(os.Args)
}
