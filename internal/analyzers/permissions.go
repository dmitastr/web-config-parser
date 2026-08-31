package analyzers

import (
	"regexp"
	"strconv"

	"web-config-parser/internal/models"
)

// permissionKeyPattern ловит имена полей, где обычно указываются права доступа
// к файлам/директориям в файловой системе.
var permissionKeyPattern = regexp.MustCompile(
	`(?i)(^permissions?$|^perm$|^mode$|file_mode|dir_mode|^chmod$|umask|access_mode|^acl$)`,
)

// worldOrGroupWritable — маска, проверяющая биты записи для группы и остальных
// пользователей (0o0ww, где ww включает group-write и other-write).
const worldOrGroupWritable = 0o022

// PermissionsAnalyzer находит слишком широкие права доступа к файлам/директориям
// (запись для группы и/или остальных пользователей, включая классическое 777/666).
//
// CWE-732: Incorrect Permission Assignment for Critical Resource
type PermissionsAnalyzer struct{}

func (a *PermissionsAnalyzer) FieldMatch(field string, _ string) bool {
	return permissionKeyPattern.MatchString(field)
}

// GetFinding возвращает finding, только если значение поля распознано как
// восьмеричные права доступа и в них выставлен бит записи для группы или
// остальных пользователей.
func (a *PermissionsAnalyzer) GetFinding(value any, _ string, path string) (*models.Finding, bool) {
	mode, ok := parsePermissionMode(value)
	if !ok {
		return nil, true
	}

	if mode&worldOrGroupWritable == 0 {
		return nil, true
	}

	return &models.Finding{
		Value:        value,
		Path:         path,
		Level:        models.LevelMedium,
		ShortMessage: "слишком широкие права доступа",
		FullMessage: `права доступа разрешают запись группе и/или всем пользователям, что позволяет ` +
			`посторонним процессам изменять файл/директорию. Рекомендация: ограничить права минимально ` +
			`необходимыми (например, 0640 для файлов, 0750 для директорий), запись должна быть только у владельца`,
	}, false
}

// parsePermissionMode приводит значение поля к восьмеричным правам доступа.
// Поддерживает строковое ("0777", "777") и числовое (777, 0777 как JSON-число)
// представление, где цифры интерпретируются как восьмеричные, а не десятичные.
func parsePermissionMode(value any) (mode uint32, ok bool) {
	switch v := value.(type) {
	case string:
		parsed, err := strconv.ParseUint(v, 8, 32)
		if err != nil {
			return 0, false
		}
		return uint32(parsed), true

	case float64: // JSON-числа при разборе в interface{} приходят как float64
		return decimalDigitsAsOctal(int64(v))

	case int:
		return decimalDigitsAsOctal(int64(v))

	default:
		return 0, false
	}
}

// decimalDigitsAsOctal превращает число вида 777 (десятичная запись,
// в которой цифры визуально означают восьмеричные права) в реальное
// восьмеричное значение прав доступа.
func decimalDigitsAsOctal(n int64) (uint32, bool) {
	if n < 0 {
		return 0, false
	}
	parsed, err := strconv.ParseUint(strconv.FormatInt(n, 10), 8, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}
