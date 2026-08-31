package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"web-config-parser/internal/app"
	"web-config-parser/internal/config"
	"web-config-parser/internal/logging"
	"web-config-parser/internal/models"
)

func main() {
	opts := config.ParseFlags()

	log := logging.New(logrus.DebugLevel)

	configAnalyzerApp := app.NewDefault(log)
	if err := configAnalyzerApp.LoadSources(opts); err != nil {
		log.WithError(err).Error("не удалось загрузить конфиг")
		os.Exit(1)
	}

	results, err := configAnalyzerApp.Validate()
	if err != nil {
		log.WithError(err).Fatal("")
	}

	hasFindings := printReport(results)

	if hasFindings && !opts.Silent {
		os.Exit(1)
	}

}

func printReport(results []*models.Result) bool {
	hasFindings := false

	for _, result := range results {
		printSectionHeader(result.SourceName)

		if result.Error != nil {
			hasFindings = true
			fmt.Printf("%s\n\n", result.Error)
			continue
		}

		if len(result.Findings) > 0 {
			hasFindings = true
		}

		for _, finding := range result.Findings {
			fmt.Printf("%s: %s | %s, path: %s, value: %v\n",
				finding.Level, finding.ShortMessage, finding.FullMessage, finding.Path, finding.Value)
		}

		fmt.Printf("\n")
	}

	return hasFindings
}

func printSectionHeader(name string) {
	border := strings.Repeat("#", len(name)+10)

	fmt.Println(border)
	fmt.Printf("#### %s ####\n", name)
	fmt.Println(border)
}
