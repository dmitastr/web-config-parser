package analyzers

import (
	"net"
	"regexp"

	"web-config-parser/internal/models"
)

type HostAnalyzer struct {
}

func (h *HostAnalyzer) FormatValue(value any) string {
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func (h *HostAnalyzer) FieldMatch(field string, _ string) bool {
	return hostKeyPattern.MatchString(field)
}

var hostKeyPattern = regexp.MustCompile(`(?i)(^host$|_host$|^bind$|^address$|^addr$|^listen)`)

func (h *HostAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	if strVal, ok := value.(string); ok {
		ip := net.ParseIP(strVal)
		if ip == nil {
			return nil, true
		}
		return &models.Finding{
			Level:        models.LevelMedium,
			ShortMessage: "открытый 0.0.0.0",
			FullMessage: `0.0.0.0 использован в качестве адреса для биндинга сервера, сервис может случайно 
оказывается доступен из интернета. Рекомендации по исправлению - явно указать нужный адрес, включить TLS, использовать
Reverse proxy`,
		}, !ip.IsUnspecified()
	}
	return nil, true
}
