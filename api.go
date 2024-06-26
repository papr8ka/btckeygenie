/* btckeygenie v1.0.0
 * https://github.com/papr8ka/btckeygenie
 * License: MIT
 */

package btckeygenie

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/papr8ka/btckeygenie/btckey"
	"log"
	"strings"
)

func byteString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

type Address struct {
	AddressCompressed         string // Bitcoin Address (Compressed)
	PublicKeyBytesCompressed  string // Public Key Bytes (Compressed)
	PublicKeyBase64Compressed string // Public Key Base64 (Compressed)

	AddressUncompressed        string // Bitcoin Address (Uncompressed)
	PublicKeyBytesUncompressed string // Public Key Bytes (Uncompressed)
	PublicKeyBase64            string // Public Key Base64 (Uncompressed)

	PrivateKeyWIFCCompressed  string // Private Key WIFC (Compressed)
	PrivateKeyWIFUncompressed string // Private Key WIF (Uncompressed)
	PrivateKeyBytes           string // Private Key Bytes
	PrivateKeyBase64          string // Private Key Base64
}

func (address *Address) String() string {
	sb := &strings.Builder{}

	sb.WriteString(fmt.Sprintf("Address compressed: %s\n", address.AddressCompressed))
	sb.WriteString(fmt.Sprintf("Public Key Bytes compressed: %s\n", address.PublicKeyBytesCompressed))
	sb.WriteString(fmt.Sprintf("Public Key Base64 compressed: %s\n", address.PublicKeyBase64Compressed))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Bitcoin Address uncompressed: %s\n", address.AddressUncompressed))
	sb.WriteString(fmt.Sprintf("Public Key Bytes uncompressed: %s\n", address.PublicKeyBytesUncompressed))
	sb.WriteString(fmt.Sprintf("Public Key Base64 uncompressed: %s\n", address.PublicKeyBase64))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Private Key WIFC compressed: %s\n", address.PrivateKeyWIFCCompressed))
	sb.WriteString(fmt.Sprintf("Private Key WIF uncompressed: %s\n", address.PrivateKeyWIFUncompressed))
	sb.WriteString(fmt.Sprintf("Private Key Bytes: %s\n", address.PrivateKeyBytes))
	sb.WriteString(fmt.Sprintf("Private Key Base64: %s\n", address.PrivateKeyBase64))

	return sb.String()
}

func Generate() *Address {
	var private btckey.PrivateKey
	var err error
	private, err = btckey.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Generating keypair: %s\n", err)
	}

	/* Convert to Compressed Address */
	addressCompressed := private.ToAddress()
	/* Convert to Public Key Compressed Bytes (33 bytes) */
	pubBytesCompressed := private.PublicKey.ToBytes()
	pubBytesCompressedStr := byteString(pubBytesCompressed)
	pubBytesCompressedB64 := base64.StdEncoding.EncodeToString(pubBytesCompressed)

	/* Convert to Uncompressed Address */
	addressUncompressed := private.ToAddressUncompressed()
	/* Convert to Public Key Uncompresed Bytes (65 bytes) */
	pubBytesUncompressed := private.PublicKey.ToBytesUncompressed()
	pubBytesUncompressedStr := byteString(pubBytesUncompressed)
	pubBytesUncompressedB64 := base64.StdEncoding.EncodeToString(pubBytesUncompressed)

	/* Convert to WIF and WIFC */
	wif := private.ToWIF()
	wifc := private.ToWIFC()
	/* Convert to Private Key Bytes (32 bytes) */
	priBytes := private.ToBytes()
	priBytesStr := byteString(priBytes)
	priBytesB64 := base64.StdEncoding.EncodeToString(priBytes)

	return &Address{
		AddressCompressed:         addressCompressed,
		PublicKeyBytesCompressed:  pubBytesCompressedStr,
		PublicKeyBase64Compressed: pubBytesCompressedB64,

		AddressUncompressed:        addressUncompressed,
		PublicKeyBytesUncompressed: pubBytesUncompressedStr,
		PublicKeyBase64:            pubBytesUncompressedB64,

		PrivateKeyWIFCCompressed:  wifc,
		PrivateKeyWIFUncompressed: wif,
		PrivateKeyBytes:           priBytesStr,
		PrivateKeyBase64:          priBytesB64,
	}
}
