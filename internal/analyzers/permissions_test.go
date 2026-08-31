package analyzers

import (
	"testing"

	"web-config-parser/internal/models"
)

func TestPermissionsAnalyzer_FieldMatch(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{name: "точное совпадение permissions", field: "permissions", want: true},
		{name: "точное совпадение permission (единственное число)", field: "permission", want: true},
		{name: "точное совпадение perm", field: "perm", want: true},
		{name: "точное совпадение mode", field: "mode", want: true},
		{name: "суффикс file_mode", field: "file_mode", want: true},
		{name: "суффикс dir_mode", field: "dir_mode", want: true},
		{name: "точное совпадение chmod", field: "chmod", want: true},
		{name: "совпадение umask", field: "umask", want: true},
		{name: "совпадение access_mode", field: "access_mode", want: true},
		{name: "точное совпадение acl", field: "acl", want: true},
		{name: "регистр не важен", field: "PERMISSIONS", want: true},
		{name: "не совпадает host", field: "host", want: false},
		{name: "не совпадает произвольное поле", field: "description", want: false},
		{name: "modeled — не должно совпадать с mode как отдельное слово", field: "modeled", want: false},
		{name: "пустая строка", field: "", want: false},
	}

	analyzer := &PermissionsAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.FieldMatch(tt.field, "")
			if got != tt.want {
				t.Errorf("FieldMatch(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestPermissionsAnalyzer_GetFinding(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		path        string
		wantFinding bool // ожидается ли непустой Finding
		wantValid   bool // ожидаемое значение isValid
	}{
		{
			name:        "строка 777 — world-writable, находка",
			value:       "777",
			path:        "storage.dir_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "строка 0777 с ведущим нулём — world-writable, находка",
			value:       "0777",
			path:        "storage.dir_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "строка 666 — world-writable, находка",
			value:       "666",
			path:        "config.file_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "строка 770 — group-writable, находка",
			value:       "770",
			path:        "config.file_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "строка 640 — безопасно, находки нет",
			value:       "0640",
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "строка 644 — безопасно, находки нет",
			value:       "644",
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "строка 755 — только execute для группы/остальных, безопасно",
			value:       "755",
			path:        "config.dir_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "число float64 777 (из JSON) — world-writable, находка",
			value:       float64(777),
			path:        "storage.dir_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "число float64 644 (из JSON) — безопасно",
			value:       float64(644),
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "число int 777 — world-writable, находка",
			value:       777,
			path:        "storage.dir_mode",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "число int 750 — безопасно",
			value:       750,
			path:        "config.dir_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "отрицательное число — не распознано, находки нет",
			value:       -1,
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "символьная нотация rwx — не распознана, находки нет",
			value:       "rwxrwxrwx",
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "невалидная восьмеричная строка (цифра 8) — не распознана",
			value:       "888",
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "пустая строка — не распознана",
			value:       "",
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "bool вместо прав — не распознано, находки нет",
			value:       true,
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "nil вместо прав — не распознано, находки нет",
			value:       nil,
			path:        "config.file_mode",
			wantFinding: false,
			wantValid:   true,
		},
	}

	analyzer := &PermissionsAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding, valid := analyzer.GetFinding(tt.value, "irrelevant_field", tt.path)

			if valid != tt.wantValid {
				t.Errorf("GetFinding(%v) isValid = %v, want %v", tt.value, valid, tt.wantValid)
			}

			if tt.wantFinding && finding == nil {
				t.Fatalf("GetFinding(%v) = nil finding, want non-nil", tt.value)
			}
			if !tt.wantFinding && finding != nil {
				t.Fatalf("GetFinding(%v) = %+v, want nil finding", tt.value, finding)
			}

			if finding == nil {
				return
			}

			if finding.Path != tt.path {
				t.Errorf("Finding.Path = %q, want %q", finding.Path, tt.path)
			}
			if finding.Level != models.LevelMedium {
				t.Errorf("Finding.Level = %v, want %v", finding.Level, models.LevelMedium)
			}
			if finding.ShortMessage == "" {
				t.Error("Finding.ShortMessage не должен быть пустым")
			}
			if finding.FullMessage == "" {
				t.Error("Finding.FullMessage не должен быть пустым")
			}
			if finding.Value != tt.value {
				t.Errorf("Finding.Value = %v, want %v", finding.Value, tt.value)
			}
		})
	}
}

// TestParsePermissionMode проверяет внутренний парсинг отдельно от GetFinding,
// чтобы ошибки конвертации форматов не маскировались уровнем выше.
func TestParsePermissionMode(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		wantMode uint32
		wantOk   bool
	}{
		{name: "строка 777", value: "777", wantMode: 0o777, wantOk: true},
		{name: "строка с ведущим нулём 0640", value: "0640", wantMode: 0o640, wantOk: true},
		{name: "float64 644", value: float64(644), wantMode: 0o644, wantOk: true},
		{name: "int 750", value: 750, wantMode: 0o750, wantOk: true},
		{name: "отрицательное число", value: -1, wantMode: 0, wantOk: false},
		{name: "невалидная восьмеричная цифра", value: "999", wantMode: 0, wantOk: false},
		{name: "нечисловая строка", value: "rwx", wantMode: 0, wantOk: false},
		{name: "неподдерживаемый тип bool", value: false, wantMode: 0, wantOk: false},
		{name: "неподдерживаемый тип nil", value: nil, wantMode: 0, wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, ok := parsePermissionMode(tt.value)
			if ok != tt.wantOk {
				t.Fatalf("parsePermissionMode(%v) ok = %v, want %v", tt.value, ok, tt.wantOk)
			}
			if ok && mode != tt.wantMode {
				t.Errorf("parsePermissionMode(%v) mode = %o, want %o", tt.value, mode, tt.wantMode)
			}
		})
	}
}
