package filehash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io/ioutil"

	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

// Calc returns the hash value of the file
func Calc(hash hash.Hash, file string) []byte {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return []byte{}
	}
	hash.Reset()
	hash.Write(data)
	return hash.Sum(nil)
}

// SHA1 returns the SHA1 hash value of the file
func SHA1(file string) []byte {
	return Calc(sha1.New(), file)
}

// SHA224 returns the SHA224 hash value of the file
func SHA224(file string) []byte {
	return Calc(sha256.New224(), file)
}

// SHA256 returns the SHA256 hash value of the file
func SHA256(file string) []byte {
	return Calc(sha256.New(), file)
}

// SHA512 returns the SHA-512 hash value of the file
func SHA512(file string) []byte {
	return Calc(sha512.New(), file)
}

// SHA512_224 returns the SHA-512/224 hash value of the file
func SHA512_224(file string) []byte {
	return Calc(sha512.New512_224(), file)
}

// SHA512_256 returns the SHA-512/256 hash value of the file
func SHA512_256(file string) []byte {
	return Calc(sha512.New512_256(), file)
}

// SHA3_224 returns the SHA3-224 hash value of the file
func SHA3_224(file string) []byte {
	return Calc(sha3.New224(), file)
}

// SHA3_256 returns the SHA3-256 hash value of the file
func SHA3_256(file string) []byte {
	return Calc(sha3.New256(), file)
}

// SHA3_384 returns the SHA3-384 hash value of the file
func SHA3_384(file string) []byte {
	return Calc(sha3.New384(), file)
}

// SHA3_512 returns the SHA3-512 hash value of the file
func SHA3_512(file string) []byte {
	return Calc(sha3.New512(), file)
}

// MD4 returns the MD4 hash value of the file
func MD4(file string) []byte {
	return Calc(md4.New(), file)
}

// MD5 returns the MD5 hash value of the file
func MD5(file string) []byte {
	return Calc(md5.New(), file)
}

// CRC32_IEEE returns the CRC-32 hash value of the file using the IEEE polynomial
func CRC32_IEEE(file string) []byte {
	return Calc(crc32.NewIEEE(), file)
}

// CRC64_ISO returns the CRC-64 hash value of the file using the ISO polynomial
func CRC64_ISO(file string) []byte {
	return Calc(crc64.New(crc64.MakeTable(crc64.ISO)), file)
}

// CRC64_ECMA returns the CRC-64 hash value of the file using the ECMA polynomial
func CRC64_ECMA(file string) []byte {
	return Calc(crc64.New(crc64.MakeTable(crc64.ECMA)), file)
}

// Adler32 returns the Adler-32 hash value of the file
func Adler32(file string) []byte {
	return Calc(adler32.New(), file)
}

// FNV32 returns the 32-bit FNV-1 hash value of the file
func FNV32(file string) []byte {
	return Calc(fnv.New32(), file)
}

// FNV32a returns the 32-bit FNV-1a hash value of the file
func FNV32a(file string) []byte {
	return Calc(fnv.New32a(), file)
}

// FNV64 returns the 64-bit FNV-1 hash value of the file
func FNV64(file string) []byte {
	return Calc(fnv.New64(), file)
}

// FNV64a returns the 64-bit FNV-1a hash value of the file
func FNV64a(file string) []byte {
	return Calc(fnv.New64a(), file)
}

// RIPEMD160 returns the 64-bit RIPEMD160 hash value of the file
func RIPEMD160(file string) []byte {
	return Calc(ripemd160.New(), file)
}