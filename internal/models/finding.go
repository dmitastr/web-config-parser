package models

type Level string

const (
	LevelLow    Level = "LOW"
	LevelHigh   Level = "HIGH"
	LevelMedium Level = "MEDIUM"
)

// Finding найденная потенциальная уязвимость, ее путь и значение в конфиге и вариант решения
type Finding struct {
	Level        Level  `json:"level"`
	Path         string `json:"path"`
	Value        any    `json:"value"`
	ShortMessage string `json:"short_message"`
	FullMessage  string `json:"full_message"`
}
