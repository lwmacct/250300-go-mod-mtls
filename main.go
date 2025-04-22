package main

import (
	"fmt"

	"github.com/lwmacct/250300-go-mod-mtls/pkg/certs"
	"github.com/lwmacct/250300-go-mod-mtls/pkg/mtls"
)

func main() {
	fmt.Println("Hello, World!")

	tlsConfig, err := mtls.NewEmbedFS(&certs.EmbedFS).ServerTLSConfig()
	if err != nil {
		fmt.Printf("%v", err)
	}
	fmt.Printf("%v", tlsConfig)

}
