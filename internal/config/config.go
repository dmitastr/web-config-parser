package config

import "github.com/spf13/pflag"

type CliOptions struct {
	Silent   bool
	UseStdin bool
	Format   string
	Dir      string
	Args     []string
}

func ParseFlags() CliOptions {
	var opts CliOptions

	pflag.BoolVarP(&opts.Silent, "silent", "s", false, "не завершать процесс с ненулевым кодом при найденных проблемах")
	pflag.BoolVar(&opts.UseStdin, "stdin", false, "читать конфиг из стандартного потока ввода вместо файла")
	pflag.StringVarP(&opts.Format, "format", "f", "", "формат конфига при чтении из stdin: json|yaml (обязателен вместе с --stdin)")
	pflag.StringVarP(&opts.Dir, "dir", "d", "", "путь к папке с конфигами для рекурсивного обхода")

	pflag.Parse()
	opts.Args = pflag.Args()

	return opts
}
