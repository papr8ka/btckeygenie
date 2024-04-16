package main

import (
	"encoding/hex"
	"fmt"
	"github.com/papr8ka/btckeygenie/btckey"
)

func main() {
	b, _ := hex.DecodeString("41E962979B392D8D279F9388C094FA43E3E13D9E3CFEE8A44DE7BAF5ADA39F3E")
	fmt.Println(btckey.PrivateKeyBytesToWIF(b))
}
