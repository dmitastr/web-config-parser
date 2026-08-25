package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"web-config-parser/internal/models"
	"web-config-parser/internal/parsers"
)

type Level string

const (
	low    Level = "LOW"
	high   Level = "HIGH"
	medium Level = "MEDIUM"
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

type ParseResult struct {
	Level        Level  `json:"level"`
	ShortMessage string `json:"short_message"`
	FullMessage  string `json:"full_message"`
}

type App struct {
	log     *logrus.Logger
	parsers map[FileExtension]parsers.Parser
	config  *models.Config
}

func NewApp(log *logrus.Logger) *App {
	return &App{
		log: log,
		parsers: map[FileExtension]parsers.Parser{
			jsonFormat: &parsers.JsonParser{},
			yamlFormat: &parsers.YAMLParser{},
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
	p.config = config
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

func (p *App) Validate() ([]*ParseResult, error) {
	if p.config.App == nil {
		warning := &ParseResult{
			Level:        high,
			ShortMessage: "app section is missing",
			FullMessage:  "app section is missing",
		}
		return []*ParseResult{warning}, nil
	}
	return nil, nil
}
