package analyzers

import (
	"fmt"

	"web-config-parser/internal/models"
)

// ConfigAnalyzer позволяет рекурсивно обойти конфиг и выявить потенциальные уязвимости
// в заданных полях по заданному правилу
type ConfigAnalyzer struct {
	fieldMatchFunc      func(key string, path string) bool // функция для фильтрации только определённых полей конфига
	isValidFunc         func(any) bool                     // функция для валидации значения, ошибка=false
	level               models.Level                       // критичность уязвимости
	shortMessage        string                             // краткое сообщение об уязвимости
	fullMessageTemplate string                             // полное сообщение с рекомендацией, содержит в себе путь поля внутри конфига и отформатированное значение
	valueFormatFunc     func(any) string                   // функция для печати значения поля, например, для скрытия паролей
}

func NewConfigAnalyzer() *ConfigAnalyzer {
	return &ConfigAnalyzer{}
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

			if c.fieldMatchFunc(key, childPath) {
				if !c.isValidFunc(val) {
					var fullMessage string
					if c.valueFormatFunc != nil {
						fullMessage = fmt.Sprintf(c.fullMessageTemplate, childPath, c.valueFormatFunc(val))
					} else {
						fullMessage = fmt.Sprintf(c.fullMessageTemplate, childPath, val)
					}
					*findings = append(*findings, models.Finding{
						Level:        c.level,
						ShortMessage: c.shortMessage,
						FullMessage:  fullMessage,
					})
					continue
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
