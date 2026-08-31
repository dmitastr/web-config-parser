package analyzers

import (
	"net"
	"regexp"

	"web-config-parser/internal/models"
)

// hostKeyPattern ловит имена полей, где обычно указывается адрес для биндинга.
var hostKeyPattern = regexp.MustCompile(`(?i)(^host$|_host$|^bind$|^address$|^addr$|^listen)`)

// HostAnalyzer находит биндинг на все сетевые интерфейсы (0.0.0.0 или его
// IPv6-эквивалент ::) без явных ограничений.
//
// CWE-1327: Binding to an Unrestricted IP Address
type HostAnalyzer struct{}

func (h *HostAnalyzer) FieldMatch(field string, _ string) bool {
	return hostKeyPattern.MatchString(field)
}

// GetFinding возвращает finding, только если значение поля — валидный IP,
// биндящийся на все интерфейсы. Если значение не похоже на IP (например,
// "example.com") или явно указывает на конкретный интерфейс — finding не строится.
func (h *HostAnalyzer) GetFinding(value any, _ string, path string) (*models.Finding, bool) {
	strVal, ok := value.(string)
	if !ok {
		return nil, true
	}

	ip := net.ParseIP(strVal)
	if ip == nil || !ip.IsUnspecified() {
		return nil, true
	}

	return &models.Finding{
		Value:        strVal,
		Path:         path,
		Level:        models.LevelMedium,
		ShortMessage: "открытый 0.0.0.0",
		FullMessage: `0.0.0.0 использован в качестве адреса для биндинга сервера, сервис может случайно 
оказывается доступен из интернета. Рекомендации по исправлению - явно указать нужный адрес, включить TLS, использовать
Reverse proxy`,
	}, false
}
