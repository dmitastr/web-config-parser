package app

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"web-config-parser/internal/analyzers"
	"web-config-parser/internal/config"
	"web-config-parser/internal/models"
	"web-config-parser/internal/parsers"
)

type FileExtension string

const (
	jsonFormat FileExtension = "json"
	yamlFormat FileExtension = "yaml"
	ymlFormat  FileExtension = "yml"
)

var (
	ErrInvalidFileExtension = errors.New("invalid file extension")
	ErrAppNotFound          = errors.New("app not found")
)

type App struct {
	log            *logrus.Logger
	parsers        map[FileExtension]parsers.Parser
	configAnalyzer *analyzers.ConfigAnalyzer
	sources        []*models.Source
	Results        []*models.Result
}

func NewDefault(log *logrus.Logger) *App {
	analyzer := analyzers.NewConfigAnalyzer(
		&analyzers.HostAnalyzer{},
		&analyzers.PlaintextSecretAnalyzer{},
		&analyzers.DebugModeAnalyzer{},
		&analyzers.OldCipherAlgoAnalyzer{},
		&analyzers.TLSDisableAnalyzer{},
	)
	return NewApp(analyzer, log)
}

func NewApp(analyzer *analyzers.ConfigAnalyzer, log *logrus.Logger) *App {
	return &App{
		log: log,
		parsers: map[FileExtension]parsers.Parser{
			jsonFormat: &parsers.JsonParser{},
			yamlFormat: &parsers.YAMLParser{},
			ymlFormat:  &parsers.YAMLParser{},
		},
		configAnalyzer: analyzer,
	}
}

func (p *App) Load(r io.ReadCloser, format FileExtension, sourceName string) error {
	cfg, err := p.load(r, format)
	if err != nil {
		return err
	}

	src := &models.Source{
		Path:    sourceName,
		Content: cfg,
	}
	p.sources = append(p.sources, src)
	return nil
}

func (p *App) load(r io.ReadCloser, format FileExtension) (any, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read cfg data: %w", err)
	}

	parser, ok := p.GetParser(format)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidFileExtension, format)
	}
	cfg, err := parser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse cfg data: %w", err)
	}

	return cfg, nil
}

func (p *App) LoadFile(fileName string) error {
	f, err := p.loadFile(fileName)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	fileExt := getFileExtention(fileName)

	return p.Load(f, fileExt, fileName)
}

func (p *App) loadFile(fileName string) (io.ReadCloser, error) {
	return os.Open(fileName)
}

func (p *App) LoadDir(dir string) error {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := getFileExtention(path)
		if _, ok := p.parsers[ext]; ok && !d.IsDir() {
			p.sources = append(p.sources, &models.Source{Path: path})
		}
		return nil
	})

	if err != nil {
		p.log.WithError(err).Error("failed to walk dir")
		return err
	}
	return nil
}

func (p *App) Validate() ([]*models.Result, error) {
	results := make([]*models.Result, 0)
	for _, src := range p.sources {
		results = append(results, p.validateSource(src))
	}
	return results, nil
}

func (p *App) validateSource(src *models.Source) *models.Result {
	if src.Content == nil {
		content, err := p.readContent(src.Path)
		if err != nil {
			return &models.Result{SourceName: src.Path, Error: err}
		}
		src.Content = content
	}

	findings, err := p.configAnalyzer.Analyze(src.Content)
	return &models.Result{SourceName: src.Path, Findings: findings, Error: err}
}

func (p *App) readContent(path string) (any, error) {
	f, err := p.loadFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ext := getFileExtention(path)
	return p.load(f, ext)
}

func getFileExtention(fName string) FileExtension {
	ext := filepath.Ext(fName)
	return FileExtension(strings.TrimPrefix(ext, "."))
}

func (p *App) LoadSources(opts config.CliOptions) error {
	sourcesSelected := 0
	if opts.Dir != "" {
		sourcesSelected++
	}
	if opts.UseStdin {
		sourcesSelected++
	}
	if len(opts.Args) > 0 {
		sourcesSelected++
	}

	switch {
	case sourcesSelected > 1:
		return fmt.Errorf("укажите только один источник конфига: --dir, --stdin или путь к файлу")

	case len(opts.Args) > 1:
		return fmt.Errorf("указано несколько файлов (%v), поддерживается только один путь", opts.Args)

	case opts.Dir != "":
		if err := p.LoadDir(opts.Dir); err != nil {
			return fmt.Errorf("загрузка директории %q: %w", opts.Dir, err)
		}
		return nil

	case opts.UseStdin:
		if opts.Format == "" {
			return fmt.Errorf("при использовании --stdin обязателен флаг --format (json|yaml)")
		}
		if err := p.Load(os.Stdin, FileExtension(opts.Format), "stdin"); err != nil {
			return fmt.Errorf("загрузка конфига из stdin: %w", err)
		}
		return nil

	case len(opts.Args) == 1:
		if err := p.LoadFile(opts.Args[0]); err != nil {
			return fmt.Errorf("загрузка конфига из файла %s: %w", opts.Args[0], err)
		}
		return nil

	default:
		return fmt.Errorf("укажите путь к файлу конфига, --dir или флаг --stdin")
	}
}

func (p *App) GetParser(format FileExtension) (parsers.Parser, bool) {
	parser, ok := p.parsers[format]
	return parser, ok
}
