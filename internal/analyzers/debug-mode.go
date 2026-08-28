package analyzers

import (
	"fmt"
	"regexp"

	"web-config-parser/internal/models"
)

type DebugModeAnalyzer struct {
}

func (a *DebugModeAnalyzer) FormatValue(value any) string {
	return fmt.Sprintf("%v", value)
}

func (a *DebugModeAnalyzer) FieldMatch(field string, _ string) bool {
	return debugKeyPattern.MatchString(field)
}

var debugKeyPattern = regexp.MustCompile(
	`(?i)(^debug$|debug_mode|^verbose$|dev_mode|developer_mode|^pprof|introspection|expose_errors|stack_trace|swagger_enabled|playground_enabled)`,
)

func (a *DebugModeAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	if boolVal, ok := value.(bool); ok {
		return &models.Finding{
			Level:        models.LevelMedium,
			ShortMessage: "debug mode в продакшн",
			FullMessage:  `включен debug mode, потенциальный источник информации для атакующего`,
		}, !boolVal
	}
	return nil, true
}
