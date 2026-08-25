package parsers

import (
	"web-config-parser/internal/models"
)

type Parser interface {
	Parse(content []byte) (*models.Config, error)
	GetField(name string) (Parser, error)
	GetValue() any
}
