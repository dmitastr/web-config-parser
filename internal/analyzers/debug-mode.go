package analyzers

import (
	"regexp"
	"strconv"

	"web-config-parser/internal/models"
)

// debugKeyPattern ловит имена полей, которые обычно управляют debug-режимом,
// подробным логированием или отладочными эндпоинтами.
var debugKeyPattern = regexp.MustCompile(
	`(?i)(^debug$|debug_mode|^verbose$|dev_mode|developer_mode|^pprof|introspection|expose_errors|stack_trace|swagger_enabled|playground_enabled)`,
)

// DebugModeAnalyzer находит включённый debug-режим и связанные с ним настройки
// (verbose-логирование, pprof, introspection и т.д.), которые в продакшене
// раскрывают внутреннее состояние приложения атакующему.
//
// CWE-489: Active Debug Code
type DebugModeAnalyzer struct{}

func (a *DebugModeAnalyzer) FieldMatch(field string, _ string) bool {
	return debugKeyPattern.MatchString(field)
}

// GetFinding возвращает finding, только если значение поля явно указывает
// на включённый debug-режим (true в любом из поддерживаемых представлений).
// Второй возвращаемый параметр всегда согласован с тем, nil ли finding.
func (a *DebugModeAnalyzer) GetFinding(value any, _ string, path string) (*models.Finding, bool) {
	enabled, ok := asBool(value)
	if !ok || !enabled {
		return nil, true
	}

	return &models.Finding{
		Level:        models.LevelMedium,
		ShortMessage: "debug mode в продакшн",
		FullMessage:  "включен debug mode, потенциальный источник информации для атакующего",
		Value:        value,
		Path:         path,
	}, false
}

// asBool приводит значение поля к bool, поддерживая не только настоящий JSON/YAML
// bool, но и строковые представления ("true"/"1"/"yes"), которые встречаются
// в конфигах, где флаг сериализован как строка.
func asBool(value any) (result bool, ok bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		if parsed, err := strconv.ParseBool(v); err == nil {
			return parsed, true
		}
		return false, false
	default:
		return false, false
	}
}
