package analyzers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"web-config-parser/internal/models"
)

func TestOldCipherAlgoAnalyzer_FieldMatch(t *testing.T) {
	t.Parallel()

	analyzer := &OldCipherAlgoAnalyzer{}

	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{
			name:  "algorithm",
			field: "algorithm",
			want:  true,
		},
		{
			name:  "algorithm with prefix",
			field: "encryption_algorithm",
			want:  true,
		},
		{
			name:  "algo suffix",
			field: "cipher_algo",
			want:  true,
		},
		{
			name:  "cipher",
			field: "cipher",
			want:  true,
		},
		{
			name:  "hash method",
			field: "hash_method",
			want:  true,
		},
		{
			name:  "hash algo",
			field: "hash_algo",
			want:  true,
		},
		{
			name:  "signing method",
			field: "signing_method",
			want:  true,
		},
		{
			name:  "sign method",
			field: "sign_method",
			want:  true,
		},
		{
			name:  "digest",
			field: "digest",
			want:  true,
		},
		{
			name:  "encryption",
			field: "encryption",
			want:  true,
		},
		{
			name:  "crypto",
			field: "crypto",
			want:  true,
		},
		{
			name:  "case insensitive",
			field: "EnCrYpTiOn_Algorithm",
			want:  true,
		},
		{
			name:  "ordinary field",
			field: "username",
			want:  false,
		},
		{
			name:  "password",
			field: "password",
			want:  false,
		},
		{
			name:  "timeout",
			field: "timeout",
			want:  false,
		},
		{
			name:  "empty field",
			field: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := analyzer.FieldMatch(tt.field, "")

			require.Equal(t, tt.want, got)
		})
	}
}

func TestOldCipherAlgoAnalyzer_GetFinding(t *testing.T) {
	t.Parallel()

	analyzer := &OldCipherAlgoAnalyzer{}

	tests := []struct {
		name        string
		value       any
		path        string
		wantFinding *models.Finding
		wantOK      bool
	}{
		{
			name:  "md5",
			value: "md5",
			path:  "security.hash",
			wantFinding: &models.Finding{
				Path:         "security.hash",
				Value:        "md5",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "алгоритм скомпрометирован, возможны коллизии",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "sha1",
			value: "sha1",
			path:  "security.hash",
			wantFinding: &models.Finding{
				Path:         "security.hash",
				Value:        "sha1",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "устарел, продемонстрированы атаки на коллизии",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "des",
			value: "des",
			path:  "tls.cipher",
			wantFinding: &models.Finding{
				Path:         "tls.cipher",
				Value:        "des",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "56-битный ключ, вскрывается перебором",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "rc4",
			value: "rc4",
			path:  "tls.cipher",
			wantFinding: &models.Finding{
				Path:         "tls.cipher",
				Value:        "rc4",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "потоковый шифр скомпрометирован",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "ssl3",
			value: "ssl3",
			path:  "tls.version",
			wantFinding: &models.Finding{
				Path:         "tls.version",
				Value:        "ssl3",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "уязвим к атаке POODLE",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "tls 1.0",
			value: "TLS 1.0",
			path:  "tls.version",
			wantFinding: &models.Finding{
				Path:         "tls.version",
				Value:        "TLS 1.0",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "устарел согласно PCI DSS и не поддерживается основными браузерами",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "jwt none",
			value: "none",
			path:  "jwt.algorithm",
			wantFinding: &models.Finding{
				Path:         "jwt.algorithm",
				Value:        "none",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "alg=none в JWT допускает подделку токена без подписи",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "ecb",
			value: "AES-128-ECB",
			path:  "encryption",
			wantFinding: &models.Finding{
				Path:         "encryption",
				Value:        "AES-128-ECB",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "не скрывает паттерны в данных, используйте GCM/CBC с корректным IV",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},
		{
			name:  "dsa",
			value: "ssh-dsa",
			path:  "ssh.host_key",
			wantFinding: &models.Finding{
				Path:         "ssh.host_key",
				Value:        "ssh-dsa",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "признан устаревшим NIST",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},

		// Проверяем normalizeAlgoName:
		// lower-case + удаление -, _, пробелов.
		{
			name:  "normalization",
			value: " S-H_A 1 ",
			path:  "hash.algorithm",
			wantFinding: &models.Finding{
				Path:         "hash.algorithm",
				Value:        " S-H_A 1 ",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "устарел, продемонстрированы атаки на коллизии",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},

		{
			name:  "case insensitive value",
			value: "MD5",
			path:  "hash.algorithm",
			wantFinding: &models.Finding{
				Path:         "hash.algorithm",
				Value:        "MD5",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "алгоритм скомпрометирован, возможны коллизии",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},

		{
			name:  "algorithm inside cipher name",
			value: "AES-128-CBC-MD5",
			path:  "cipher",
			wantFinding: &models.Finding{
				Path:         "cipher",
				Value:        "AES-128-CBC-MD5",
				ShortMessage: "устаревший алгоритм шифрования",
				FullMessage:  "алгоритм скомпрометирован, возможны коллизии",
				Level:        models.LevelMedium,
			},
			wantOK: false,
		},

		{
			name:        "safe algorithm",
			value:       "AES-256-GCM",
			path:        "encryption.algorithm",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "safe hash",
			value:       "SHA-256",
			path:        "hash.algorithm",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "empty string",
			value:       "",
			path:        "algorithm",
			wantFinding: nil,
			wantOK:      true,
		},

		// GetFinding специально принимает any.
		// Для не-string значения функция должна пропустить finding.
		{
			name:        "integer value",
			value:       123,
			path:        "algorithm",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "boolean value",
			value:       true,
			path:        "algorithm",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "nil value",
			value:       nil,
			path:        "algorithm",
			wantFinding: nil,
			wantOK:      true,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotFinding, gotOK := analyzer.GetFinding(
				tt.value,
				"",
				tt.path,
			)

			require.Equal(t, tt.wantOK, gotOK)
			require.Equal(t, tt.wantFinding, gotFinding)
		})
	}
}
