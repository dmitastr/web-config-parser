package analyzers

import (
	"fmt"

	"web-config-parser/internal/models"
)

type Analyzer interface {
	FieldMatch(key string, path string) bool // функция для фильтрации только определённых полей конфига
	IsValid(value any) bool                  // функция для валидации значения, ошибка=false
	GetFinding() models.Finding              // получить шаблон сообщения об уязвимости
	FormatValue(value any) string            //  функция для формата значения поля, например, для скрытия паролей
}

// ConfigAnalyzer позволяет рекурсивно обойти конфиг и выявить потенциальные уязвимости
// в заданных полях по заданному правилу
type ConfigAnalyzer struct {
	analyzers []Analyzer
}

func NewConfigAnalyzer(analyzers ...Analyzer) *ConfigAnalyzer {
	return &ConfigAnalyzer{analyzers: analyzers}
}
func (c *ConfigAnalyzer) Analyze(config any) ([]models.Finding, error) {
	var findings []models.Finding
	c.walk(config, "", &findings)

	return findings, nil
}

func (c *ConfigAnalyzer) walk(node interface{}, path string, findings *[]models.Finding) {
	switch v := node.(type) {

	case map[string]interface{}:
		for key, val := range v {
			childPath := joinPath(path, key)

			for _, analyzer := range c.analyzers {
				if analyzer.FieldMatch(key, childPath) {
					if !analyzer.IsValid(val) {
						value := analyzer.FormatValue(val)
						finding := analyzer.GetFinding()
						finding.Value = value
						finding.Path = childPath

						*findings = append(*findings, finding)
					}
				}
			}

			c.walk(val, childPath, findings)
		}

	case []interface{}:
		for i, item := range v {
			c.walk(item, fmt.Sprintf("%s[%d]", path, i), findings)
		}

	case string:

	}
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}
