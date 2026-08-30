package analyzers

import (
	"fmt"
	"regexp"

	"web-config-parser/internal/models"
)

// "негативные" ключи — опасно, когда значение true
var insecureFlagPattern = regexp.MustCompile(
	`(?i)(insecure_skip_verify|skip_tls_verify|skip_verify|tls_insecure|allow_insecure|disable_tls_verify|ignore_cert_errors|insecure_skip_tls_verify)`,
)

// "позитивные" ключи — опасно, когда значение false
var verifyFlagPattern = regexp.MustCompile(
	`(?i)(verify_ssl|verify_tls|verify_cert|ssl_verify|tls_verify|check_cert|validate_cert)`,
)

type TLSDisableAnalyzer struct {
}

func (a *TLSDisableAnalyzer) FormatValue(value any) string {
	return fmt.Sprintf("%v", value)
}

func (a *TLSDisableAnalyzer) FieldMatch(field string, _ string) bool {
	return insecureFlagPattern.MatchString(field) && verifyFlagPattern.MatchString(field)
}

func (a *TLSDisableAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	if boolVal, ok := value.(bool); ok {
		isFinding := (!boolVal && verifyFlagPattern.MatchString(field)) || (insecureFlagPattern.MatchString(field) && boolVal)
		return &models.Finding{
			Value:        boolVal,
			Path:         path,
			Level:        models.LevelMedium,
			ShortMessage: "отключенная TLS-проверка",
			FullMessage: `когда клиентская часть приложения настроена игнорировать проверку сертификата сервера, 
рекомендуется включить проверку `,
		}, isFinding
	}
	return nil, true
}
