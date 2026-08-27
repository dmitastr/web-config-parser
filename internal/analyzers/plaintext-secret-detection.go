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

func (p PlaintextSecretAnalyzer) IsValid(value any, field string, path string) bool {
	if strVal, ok := value.(string); ok {
		for _, re := range placeholderPatterns {
			if re.MatchString(strVal) {
				return true
			}
		}
		return false
	}
	return true
}

func (p PlaintextSecretAnalyzer) GetFinding() models.Finding {
	return models.Finding{
		Level:        models.LevelHigh,
		ShortMessage: shotMessageTemplate,
		FullMessage:  fullMessageTemplate,
	}
}

func (p PlaintextSecretAnalyzer) FormatValue(s any) string {
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
