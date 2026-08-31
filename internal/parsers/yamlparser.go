package parsers

import "gopkg.in/yaml.v3"

type YAMLParser struct {
}

func (Y YAMLParser) Parse(content []byte) (interface{}, error) {
	var config interface{}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func (Y YAMLParser) GetField(name string) (Parser, error) {
	// TODO implement me
	panic("implement me")
}

func (Y YAMLParser) GetValue() any {
	// TODO implement me
	panic("implement me")
}
