package analyzers

import (
	"regexp"

	"web-config-parser/internal/models"
)

type PlaintextSecretAnalyzer struct {
}

func (p PlaintextSecretAnalyzer) FieldMatch(field string, _ string) bool {
	return sensitiveFieldPattern.MatchString(field) && !sensitiveFieldMinusPattern.MatchString(field)
}

func (p PlaintextSecretAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	if strVal, ok := value.(string); ok {
		for _, re := range placeholderPatterns {
			if re.MatchString(strVal) {
				return nil, true
			}
		}
		return &models.Finding{
			Value:        p.formatValue(value),
			Path:         path,
			Level:        models.LevelHigh,
			ShortMessage: shotMessageTemplate,
			FullMessage:  fullMessageTemplate,
		}, false
	}
	return nil, true
}

func (p PlaintextSecretAnalyzer) formatValue(s any) string {
	strVal, ok := s.(string)
	if !ok {
		return "***"
	}
	if len(strVal) <= 4 {
		return "***"
	}
	return strVal[:2] + "***"
}

const (
	shotMessageTemplate = "пароль в открытом виде"
	fullMessageTemplate = "в поле конфига пароль хранится в открытом виде, требуется замена на переменную окружения"
)

var sensitiveFieldPattern = regexp.MustCompile(
	`(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)`,
)

var sensitiveFieldMinusPattern = regexp.MustCompile(
	`(?i)(ttl)`,
)

var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`),
	regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:-.*\}$`),
}
