package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"web-config-parser/internal/logging"
	"web-config-parser/internal/parser"
)

func main() {
	log := logging.New(logrus.DebugLevel)
	args := os.Args
	if len(args) < 2 {
		log.Fatal("Usage: go run cmd/goweb-parser path/to/config")
	}

	configFile := args[1]
	configParser := parser.NewParser(log)

	results, err := configParser.AnalyzeConfigFile(configFile)
	if err != nil {
		log.WithError(err).Fatal("Error parsing config")
		return
	}

	if len(results) != 0 {
		for _, result := range results {
			fmt.Printf("%s: %s | %s\n", result.Level, result.ShortMessage, result.FullMessage)
		}
		os.Exit(1)
	}
}
