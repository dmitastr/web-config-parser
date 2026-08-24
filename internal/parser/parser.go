package parser

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/Jeffail/gabs/v2"
)

type Level string

const (
	low    Level = "LOW"
	high   Level = "HIGH"
	medium Level = "MEDIUM"
)

const (
	json = ".json"
	yaml = ".yaml"
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
type Parser struct {
	log *logrus.Logger
}

func NewParser(log *logrus.Logger) *Parser {
	return &Parser{log: log}
}

func (p *Parser) AnalyzeConfigFile(fileName string) ([]*ParseResult, error) {
	fileExt := filepath.Ext(fileName)
	switch fileExt {
	case json:
		return p.parseJson(fileName)
	case yaml:
		return p.parseYaml(fileName)
	default:
		return nil, ErrInvalidFileExtension
	}

}
func (p *Parser) parseJson(fileName string) ([]*ParseResult, error) {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	config, err := gabs.ParseJSON(file)
	if err != nil {
		return nil, err
	}
	app := config.Search("app")
	if app == nil {
		return nil, ErrAppNotFound
	}
	return nil, nil
}

func (p *Parser) parseYaml(fileName string) ([]*ParseResult, error) {

}
