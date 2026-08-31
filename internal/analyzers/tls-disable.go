package analyzers

import (
	"fmt"
	"regexp"

	"web-config-parser/internal/models"
)

// insecureFlagPattern — "негативные" ключи: опасно, когда значение true.
var insecureFlagPattern = regexp.MustCompile(
	`(?i)(insecure_skip_verify|skip_tls_verify|skip_verify|tls_insecure|allow_insecure|disable_tls_verify|ignore_cert_errors|insecure_skip_tls_verify)`,
)

// verifyFlagPattern — "позитивные" ключи: опасно, когда значение false.
var verifyFlagPattern = regexp.MustCompile(
	`(?i)(verify_ssl|verify_tls|verify_cert|ssl_verify|tls_verify|check_cert|validate_cert)`,
)

// TLSDisableAnalyzer находит отключённую проверку TLS-сертификата на клиентской
// стороне (insecure_skip_verify=true, verify_ssl=false и аналогичные флаги).
//
// CWE-295: Improper Certificate Validation
type TLSDisableAnalyzer struct{}

func (a *TLSDisableAnalyzer) FormatValue(value any) string {
	return fmt.Sprintf("%v", value)
}

// FieldMatch срабатывает, если имя поля похоже на "негативный" ИЛИ "позитивный"
// флаг проверки TLS — поле не может (и не должно) матчиться обоим паттернам сразу.
func (a *TLSDisableAnalyzer) FieldMatch(field string, _ string) bool {
	return insecureFlagPattern.MatchString(field) || verifyFlagPattern.MatchString(field)
}

// GetFinding возвращает finding, только если булево значение поля действительно
// означает отключённую проверку TLS: true для "негативных" флагов
// (insecure_skip_verify) или false для "позитивных" (verify_ssl).
func (a *TLSDisableAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	boolVal, ok := value.(bool)
	if !ok {
		return nil, true
	}

	isDangerous := (insecureFlagPattern.MatchString(field) && boolVal) ||
		(verifyFlagPattern.MatchString(field) && !boolVal)

	if !isDangerous {
		return nil, true
	}

	return &models.Finding{
		Value:        boolVal,
		Path:         path,
		Level:        models.LevelMedium,
		ShortMessage: "отключенная TLS-проверка",
		FullMessage: `когда клиентская часть приложения настроена игнорировать проверку сертификата сервера, 
рекомендуется включить проверку `,
	}, false
}
