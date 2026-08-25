package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"web-config-parser/internal/analyzers"
	"web-config-parser/internal/models"
	"web-config-parser/internal/parsers"
)

type FileExtension string

const (
	jsonFormat FileExtension = ".json"
	yamlFormat FileExtension = ".yaml"
)

var (
	ErrInvalidFileExtension = errors.New("invalid file extension")
	ErrAppNotFound          = errors.New("app not found")
)

type App struct {
	configRaw any
	log       *logrus.Logger
	parsers   map[FileExtension]parsers.Parser
	config    *models.Config
	analyzers []analyzers.ConfigAnalyzer
}

func NewApp(log *logrus.Logger) *App {
	plaintextSecretDetector := analyzers.NewPlaintextSecretDetector()
	return &App{
		log: log,
		parsers: map[FileExtension]parsers.Parser{
			jsonFormat: &parsers.JsonParser{},
			yamlFormat: &parsers.YAMLParser{},
		},
		analyzers: []analyzers.ConfigAnalyzer{
			plaintextSecretDetector,
		},
	}
}

func (p *App) Load(r io.Reader, format FileExtension) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read config data: %w", err)
	}

	parser, ok := p.parsers[format]
	if !ok {
		return fmt.Errorf("%w: %s", ErrInvalidFileExtension, format)
	}
	config, err := parser.Parse(data)
	if err != nil {
		return fmt.Errorf("parse config data: %w", err)
	}
	p.configRaw = config
	return nil
}

func (p *App) LoadFile(fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	fileExt := filepath.Ext(fileName)

	return p.Load(f, FileExtension(fileExt))
}

func (p *App) Validate() ([]models.Finding, error) {
	result := make([]models.Finding, 0)
	for _, analyzer := range p.analyzers {
		findings, err := analyzer.Analyze(p.configRaw)
		if err != nil {
			return nil, err
		}
		result = append(result, findings...)
	}
	return result, nil
}
