package main

import (
	"os"

	wboxserver "github.com/foxcpp/wirebox/server"
)

func main() {
	os.Exit(wboxserver.Main())
}
