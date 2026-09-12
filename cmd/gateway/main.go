package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gekok/vps-egress-gateway/internal/config"
	"github.com/gekok/vps-egress-gateway/internal/gateway"
)

var (
	configPath  = flag.String("config", "config.json", "path to JSON config file")
	showVersion = flag.Bool("version", false, "print version and exit")
)

const version = "0.1.0-mvp"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "vps-egress-gateway: private CONNECT egress gateway (MVP local)\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: gateway --config <path>\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nEnv secrets are referenced by config (see config.example.json).\n")
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}
	if err := gateway.Serve(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "gateway error: %v\n", err)
		os.Exit(1)
	}
}
