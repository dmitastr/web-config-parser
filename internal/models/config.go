package models

type Config struct {
	App *struct {
		Name string `json:"name" yaml:"name"`
		Env  string `json:"env" yaml:"env"`
	} `json:"app" yaml:"app"`

	Server struct {
		Host string `json:"host" yaml:"host"`
		Port int    `json:"port" yaml:"port"`
	} `json:"server" yaml:"server"`
}
