package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"web-config-parser/internal/app"
	"web-config-parser/internal/logging"
)

func main() {
	var silent bool
	var useStdin bool
	var format string

	flag.BoolVarP(&silent, "silent", "s", false, "silent mode для ошибок")
	flag.BoolVar(&useStdin, "stdin", false, "читать конфиг из стандартного потока ввода вместо файла")
	flag.StringVarP(&format, "format", "f", "", "формат конфига при чтении из stdin: json|yaml (обязателен вместе с --stdin)")

	flag.Parse()
	args := flag.Args()

	log := logging.New(logrus.DebugLevel)
	analyzer := app.NewApp(log)

	switch {
	case useStdin && len(args) > 0:
		fmt.Printf("нельзя одновременно указывать --stdin и путь к файлу %q", args[0])
		return

	case useStdin:
		if format == "" {
			fmt.Println("при использовании --stdin обязателен флаг --format (json|yaml)")
		}
		if err := analyzer.Load(os.Stdin, app.FileExtension(format)); err != nil {
			fmt.Printf("ошибка при загрузке конфига из stdin: %v", err)
		}

	case len(args) == 1:
		if err := analyzer.LoadFile(args[0]); err != nil {
			fmt.Printf("ошибка при загрузке конфига из файла %s: %v", args[0], err)
		}

	default:
		fmt.Println("укажите путь к файлу конфига либо флаг --stdin")
	}

	results, err := analyzer.Validate()
	if err != nil {
		log.WithError(err).Fatal("")
	}

	if len(results) != 0 {
		for _, result := range results {
			fmt.Printf("%s: %s | %s\n", result.Level, result.ShortMessage, result.FullMessage)
		}
		if !silent {
			os.Exit(1)
		}
	}
}
