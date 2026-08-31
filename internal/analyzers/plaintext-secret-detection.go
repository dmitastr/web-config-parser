package analyzers

import (
	"regexp"

	"web-config-parser/internal/models"
)

// sensitiveFieldPattern ловит имена полей, которые обычно содержат секреты.
var sensitiveFieldPattern = regexp.MustCompile(
	`(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)`,
)

// sensitiveFieldMinusPattern исключает поля, которые совпадают с sensitiveFieldPattern
// по подстроке, но по смыслу секретом не являются (например, access_token_ttl).
var sensitiveFieldMinusPattern = regexp.MustCompile(`(?i)(ttl)`)

// placeholderPatterns — распознаваемые нотации подстановки переменных окружения,
// которые не считаются секретом в открытом виде.
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`),
	regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^env:[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:-.*\}$`),
}

// PlaintextSecretAnalyzer находит пароли, токены и ключи, хранящиеся в конфиге
// в открытом виде вместо плейсхолдера переменной окружения.
//
// CWE-798: Use of Hard-coded Credentials
type PlaintextSecretAnalyzer struct{}

func (p *PlaintextSecretAnalyzer) FieldMatch(field string, _ string) bool {
	return sensitiveFieldPattern.MatchString(field) && !sensitiveFieldMinusPattern.MatchString(field)
}

// GetFinding возвращает finding, только если значение поля — непустая строка,
// не являющаяся плейсхолдером переменной окружения.
func (p *PlaintextSecretAnalyzer) GetFinding(value any, _ string, path string) (*models.Finding, bool) {
	strVal, ok := value.(string)
	if !ok || strVal == "" {
		return nil, true
	}

	for _, re := range placeholderPatterns {
		if re.MatchString(strVal) {
			return nil, true
		}
	}

	return &models.Finding{
		Value:        p.formatValue(strVal),
		Path:         path,
		Level:        models.LevelHigh,
		ShortMessage: "пароль в открытом виде",
		FullMessage:  "в поле конфига пароль хранится в открытом виде, требуется замена на переменную окружения",
	}, false
}

func (p *PlaintextSecretAnalyzer) formatValue(strVal string) string {
	if len(strVal) <= 4 {
		return "***"
	}
	return strVal[:2] + "***"
}
