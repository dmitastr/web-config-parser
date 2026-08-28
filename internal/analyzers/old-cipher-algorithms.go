package analyzers

import (
	"fmt"
	"regexp"
	"strings"

	"web-config-parser/internal/models"
)

var algoKeyPattern = regexp.MustCompile(
	`(?i)(algorithm|algo$|cipher|hash_?method|hash_?algo|signing_method|sign_method|digest|encryption$|crypto)`,
)

// известные небезопасные/устаревшие значения — независимо от того, в каком поле встретились
var deprecatedAlgorithms = map[string]string{
	// хэш-функции
	"md5":  "алгоритм скомпрометирован, возможны коллизии",
	"sha1": "устарел, продемонстрированы атаки на коллизии",
	"des":  "56-битный ключ, вскрывается перебором",
	"3des": "признан устаревшим NIST с 2023 года",
	"rc4":  "потоковый шифр скомпрометирован",
	"rc2":  "устаревший, слабый алгоритм",

	// TLS/SSL версии
	"ssl2":    "полностью скомпрометирован",
	"ssl3":    "уязвим к атаке POODLE",
	"sslv2":   "полностью скомпрометирован",
	"sslv3":   "уязвим к атаке POODLE",
	"tls1.0":  "устарел согласно PCI DSS и не поддерживается основными браузерами",
	"tlsv1":   "устарел согласно PCI DSS и не поддерживается основными браузерами",
	"tls1.1":  "устарел согласно PCI DSS и не поддерживается основными браузерами",
	"tlsv1.1": "устарел согласно PCI DSS и не поддерживается основными браузерами",

	// JWT / подпись
	"none": "alg=none в JWT допускает подделку токена без подписи",
	"hs1":  "слабый вариант HMAC",

	// шифрование в целом
	"ecb": "не скрывает паттерны в данных, используйте GCM/CBC с корректным IV",

	// SSH
	"ssh-dss": "DSA устарел и считается слабым",
	"dsa":     "признан устаревшим NIST",
}

type OldCipherAlgoAnalyzer struct {
}

func (a *OldCipherAlgoAnalyzer) FormatValue(value any) string {
	return fmt.Sprintf("%v", value)
}

func (a *OldCipherAlgoAnalyzer) FieldMatch(field string, _ string) bool {
	return algoKeyPattern.MatchString(field)
}

func (a *OldCipherAlgoAnalyzer) GetFinding(value any, field string, path string) (*models.Finding, bool) {
	strValue, ok := value.(string)
	if ok {
		return nil, true
	}
	normalized := normalizeAlgoName(strValue)

	for algo, reason := range deprecatedAlgorithms {
		if normalized == algo || strings.Contains(normalized, algo) {
			return &models.Finding{
				Path:         path,
				Value:        value,
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  reason,
				Level:        models.LevelMedium,
			}, false
		}
	}
	return nil, true
}

func normalizeAlgoName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
