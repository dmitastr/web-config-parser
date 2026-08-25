package parsers

import "web-config-parser/internal/models"

type YAMLParser struct {
}

func (Y YAMLParser) Parse(content []byte) (*models.Config, error) {
	// TODO implement me
	panic("implement me")
}

func (Y YAMLParser) GetField(name string) (Parser, error) {
	// TODO implement me
	panic("implement me")
}

func (Y YAMLParser) GetValue() any {
	// TODO implement me
	panic("implement me")
}
