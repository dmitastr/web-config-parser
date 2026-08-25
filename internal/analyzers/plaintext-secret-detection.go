package analyzers

import (
	"regexp"

	"web-config-parser/internal/models"
)

const (
	shotMessageTemplate = "пароль в открытом виде"
	fullMessageTemplate = "в поле конфига %s пароль хранится в открытом виде: %s"
)

var sensitiveFieldPattern = regexp.MustCompile(
	`(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)`,
)

var sensitiveFieldMinusPattern = regexp.MustCompile(
	`(?i)(ttl)`,
)

func IsPasswordFiled(field string, _ string) bool {
	return sensitiveFieldPattern.MatchString(field) && !sensitiveFieldMinusPattern.MatchString(field)
}

var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`),
	regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:-.*\}$`),
}

func IsEnvPlaceholder(value any) bool {
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

func truncate(s any) string {
	strVal, ok := s.(string)
	if !ok {
		return "***"
	}
	if len(strVal) <= 4 {
		return "***"
	}
	return strVal[:2] + "***"
}

func NewPlaintextSecretDetector() ConfigAnalyzer {
	return ConfigAnalyzer{
		fieldMatchFunc:      IsPasswordFiled,
		isValidFunc:         IsEnvPlaceholder,
		level:               models.LevelHigh,
		shortMessage:        shotMessageTemplate,
		fullMessageTemplate: fullMessageTemplate,
		valueFormatFunc:     truncate,
	}
}
