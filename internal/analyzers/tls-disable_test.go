package analyzers

import (
	"testing"

	"web-config-parser/internal/models"
)

func TestTLSDisableAnalyzer_FieldMatch(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{name: "insecure_skip_verify", field: "insecure_skip_verify", want: true},
		{name: "skip_tls_verify", field: "skip_tls_verify", want: true},
		{name: "skip_verify", field: "skip_verify", want: true},
		{name: "tls_insecure", field: "tls_insecure", want: true},
		{name: "allow_insecure", field: "allow_insecure", want: true},
		{name: "disable_tls_verify", field: "disable_tls_verify", want: true},
		{name: "ignore_cert_errors", field: "ignore_cert_errors", want: true},
		{name: "verify_ssl", field: "verify_ssl", want: true},
		{name: "verify_tls", field: "verify_tls", want: true},
		{name: "verify_cert", field: "verify_cert", want: true},
		{name: "ssl_verify", field: "ssl_verify", want: true},
		{name: "check_cert", field: "check_cert", want: true},
		{name: "validate_cert", field: "validate_cert", want: true},
		{name: "регистр не важен", field: "INSECURE_SKIP_VERIFY", want: true},
		{name: "не совпадает host", field: "host", want: false},
		{name: "не совпадает произвольное поле", field: "description", want: false},
		{name: "пустая строка", field: "", want: false},
	}

	analyzer := &TLSDisableAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.FieldMatch(tt.field, "")
			if got != tt.want {
				t.Errorf("FieldMatch(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestTLSDisableAnalyzer_GetFinding(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		field       string
		path        string
		wantFinding bool
		wantValid   bool
	}{
		{
			name:        "insecure_skip_verify=true — опасно, находка",
			value:       true,
			field:       "insecure_skip_verify",
			path:        "http_client.insecure_skip_verify",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "insecure_skip_verify=false — безопасно, находки нет",
			value:       false,
			field:       "insecure_skip_verify",
			path:        "http_client.insecure_skip_verify",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "skip_tls_verify=true — опасно, находка",
			value:       true,
			field:       "skip_tls_verify",
			path:        "grpc.skip_tls_verify",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "verify_ssl=false — опасно, находка",
			value:       false,
			field:       "verify_ssl",
			path:        "external_api.verify_ssl",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "verify_ssl=true — безопасно, находки нет",
			value:       true,
			field:       "verify_ssl",
			path:        "external_api.verify_ssl",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "verify_cert=false — опасно, находка",
			value:       false,
			field:       "verify_cert",
			path:        "smtp.verify_cert",
			wantFinding: true,
			wantValid:   false,
		},
		{
			name:        "check_cert=true — безопасно, находки нет",
			value:       true,
			field:       "check_cert",
			path:        "smtp.check_cert",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "не bool (строка) — не распознано, находки нет",
			value:       "true",
			field:       "insecure_skip_verify",
			path:        "http_client.insecure_skip_verify",
			wantFinding: false,
			wantValid:   true,
		},
		{
			name:        "nil — не распознано, находки нет",
			value:       nil,
			field:       "verify_ssl",
			path:        "external_api.verify_ssl",
			wantFinding: false,
			wantValid:   true,
		},
	}

	analyzer := &TLSDisableAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding, valid := analyzer.GetFinding(tt.value, tt.field, tt.path)

			if valid != tt.wantValid {
				t.Errorf("GetFinding(%v, %q) isValid = %v, want %v", tt.value, tt.field, valid, tt.wantValid)
			}

			if tt.wantFinding && finding == nil {
				t.Fatalf("GetFinding(%v, %q) = nil finding, want non-nil", tt.value, tt.field)
			}
			if !tt.wantFinding && finding != nil {
				t.Fatalf("GetFinding(%v, %q) = %+v, want nil finding", tt.value, tt.field, finding)
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
			if finding.Value != tt.value {
				t.Errorf("Finding.Value = %v, want %v", finding.Value, tt.value)
			}
			if finding.ShortMessage == "" {
				t.Error("Finding.ShortMessage не должен быть пустым")
			}
			if finding.FullMessage == "" {
				t.Error("Finding.FullMessage не должен быть пустым")
			}
		})
	}
}

func TestTLSDisableAnalyzer_FormatValue(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "bool true", value: true, want: "true"},
		{name: "bool false", value: false, want: "false"},
		{name: "строка", value: "abc", want: "abc"},
		{name: "nil", value: nil, want: "<nil>"},
	}

	analyzer := &TLSDisableAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.FormatValue(tt.value)
			if got != tt.want {
				t.Errorf("FormatValue(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
