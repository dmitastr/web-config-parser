package parsers

import (
	"encoding/json"
	"errors"

	"github.com/Jeffail/gabs/v2"
	"web-config-parser/internal/models"
)

type JsonParser struct {
	container *gabs.Container
}

func (j *JsonParser) Parse(content []byte) (*models.Config, error) {
	var config models.Config
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (j *JsonParser) GetField(name string) (Parser, error) {
	c := j.container.Search(name)
	if c == nil {
		return nil, errors.New("field '" + name + "' not found")
	}
	return &JsonParser{container: c}, nil
}

func (j *JsonParser) GetValue() any {
	return j.container.Data()
}
