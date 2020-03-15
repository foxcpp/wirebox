package main

import (
	"os"

	wboxclient "github.com/foxcpp/wirebox/client"
)

func main() {
	os.Exit(wboxclient.Main())
}
