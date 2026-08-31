package analyzers

import (
	"testing"

	"web-config-parser/internal/models"
)

func TestPlaintextSecretAnalyzer_FieldMatch(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{name: "password", field: "password", want: true},
		{name: "passwd", field: "passwd", want: true},
		{name: "pwd", field: "pwd", want: true},
		{name: "secret", field: "jwt_secret", want: true},
		{name: "token", field: "auth_token", want: true},
		{name: "api_key с подчёркиванием", field: "api_key", want: true},
		{name: "api-key с дефисом", field: "api-key", want: true},
		{name: "private_key", field: "private_key", want: true},
		{name: "access_key", field: "access_key", want: true},
		{name: "credential", field: "db_credential", want: true},
		{name: "регистр не важен", field: "PASSWORD", want: true},
		{name: "access_token_ttl исключается по ttl", field: "access_token_ttl", want: false},
		{name: "refresh_token_ttl исключается по ttl", field: "refresh_token_ttl", want: false},
		{name: "не совпадает host", field: "host", want: false},
		{name: "не совпадает произвольное поле", field: "description", want: false},
		{name: "пустая строка", field: "", want: false},
	}

	analyzer := &PlaintextSecretAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.FieldMatch(tt.field, "")
			if got != tt.want {
				t.Errorf("FieldMatch(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestPlaintextSecretAnalyzer_GetFinding(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		path        string
		wantFinding bool
		wantValid   bool
		wantValue   string // ожидаемое значение Finding.Value, проверяется только если wantFinding
	}{
		{
			name:        "plaintext пароль длиннее 4 символов — находка, маскируется",
			value:       "hunter2",
			path:        "database.password",
			wantFinding: true,
			wantValid:   false,
			wantValue:   "hu***",
		},
		{
			name:        "plaintext пароль короче 4 символов — находка, полностью маскируется",
			value:       "abc",
			path:        "database.password",
			wantFinding: true,
			wantValid:   false,
			wantValue:   "***",
		},
		{
			name:        "plaintext пароль ровно 4 символа — полностью маскируется",
			value:       "abcd",
			path:        "database.password",
			wantFinding: true,
			wantValid:   false,
			wantValue:   "***",
		},
		{
			name:        "пустая строка — не считается секретом, находки нет",
			value:       "",
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "плейсхолдер ${VAR} — безопасно",
			value:       "${DB_PASSWORD}",
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "плейсхолдер $VAR — безопасно",
			value:       "$DB_PASSWORD",
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "плейсхолдер env:VAR — безопасно",
			value:       "env:DB_PASSWORD",
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "плейсхолдер с дефолтом ${VAR:-default} — безопасно",
			value:       "${DB_PASSWORD:-changeme}",
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "похоже на плейсхолдер, но без фигурных скобок и с пробелом — не считается плейсхолдером",
			value:       "$DB PASSWORD",
			path:        "database.password",
			wantFinding: true,
			wantValid:   false,
			wantValue:   "$D***",
		},
		{
			name:        "не строка (число) — не распознано, находки нет",
			value:       12345,
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "не строка (bool) — не распознано, находки нет",
			value:       true,
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "nil — не распознано, находки нет",
			value:       nil,
			path:        "database.password",
			wantFinding: false,
			wantValid:   true,
		},
	}

	analyzer := &PlaintextSecretAnalyzer{}

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
			if finding.Level != models.LevelHigh {
				t.Errorf("Finding.Level = %v, want %v", finding.Level, models.LevelHigh)
			}
			if finding.ShortMessage == "" {
				t.Errorf("Finding.ShortMessage is empty")
			}
			if finding.FullMessage == "" {
				t.Errorf("Finding.FullMessage is empty")
			}
			if finding.Value != tt.wantValue {
				t.Errorf("Finding.Value = %q, want %q (raw secret must never leak into the report)", finding.Value, tt.wantValue)
			}
		})
	}
}

// TestPlaintextSecretAnalyzer_formatValue проверяет маскирование значения отдельно,
// чтобы не смешивать проверку форматирования с проверкой правил обнаружения.
func TestPlaintextSecretAnalyzer_formatValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "пустая строка", value: "", want: "***"},
		{name: "1 символ", value: "a", want: "***"},
		{name: "4 символа — граница", value: "abcd", want: "***"},
		{name: "5 символов — уже маскируется частично", value: "abcde", want: "ab***"},
		{name: "длинный секрет", value: "sk-abc123def456", want: "sk***"},
	}

	analyzer := &PlaintextSecretAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.formatValue(tt.value)
			if got != tt.want {
				t.Errorf("formatValue(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
