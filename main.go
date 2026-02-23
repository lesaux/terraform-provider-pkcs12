package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"terraform-provider-pkcs12/pkcs12"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/kinaxis/pkcs12",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), pkcs12.New, opts)
	if err != nil {
		log.Fatal(err)
	}
}
