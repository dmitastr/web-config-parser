package analyzers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"web-config-parser/internal/models"
)

func TestHostAnalyzer_FieldMatch(t *testing.T) {
	t.Parallel()

	analyzer := &HostAnalyzer{}

	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{
			name:  "host",
			field: "host",
			want:  true,
		},
		{
			name:  "host with prefix",
			field: "server_host",
			want:  true,
		},
		{
			name:  "bind",
			field: "bind",
			want:  true,
		},
		{
			name:  "address",
			field: "address",
			want:  true,
		},
		{
			name:  "addr",
			field: "addr",
			want:  true,
		},
		{
			name:  "listen",
			field: "listen",
			want:  true,
		},
		{
			name:  "listen with suffix",
			field: "listen_address",
			want:  true,
		},
		{
			name:  "uppercase host",
			field: "HOST",
			want:  true,
		},
		{
			name:  "mixed case address",
			field: "AdDrEsS",
			want:  true,
		},
		{
			name:  "uppercase bind",
			field: "BIND",
			want:  true,
		},
		{
			name:  "ordinary field",
			field: "username",
			want:  false,
		},
		{
			name:  "port",
			field: "port",
			want:  false,
		},
		{
			name:  "hostname",
			field: "hostname",
			want:  false,
		},
		{
			name:  "remote host",
			field: "remote",
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

func TestHostAnalyzer_GetFinding(t *testing.T) {
	t.Parallel()

	analyzer := &HostAnalyzer{}

	const expectedMessage = `0.0.0.0 использован в качестве адреса для биндинга сервера, сервис может случайно 
оказывается доступен из интернета. Рекомендации по исправлению - явно указать нужный адрес, включить TLS, использовать
Reverse proxy`

	tests := []struct {
		name        string
		value       any
		path        string
		wantFinding *models.Finding
		wantOK      bool
	}{
		{
			name:  "IPv4 unspecified address",
			value: "0.0.0.0",
			path:  "server.host",
			wantFinding: &models.Finding{
				Value:        "0.0.0.0",
				Path:         "server.host",
				Level:        models.LevelMedium,
				ShortMessage: "открытый 0.0.0.0",
				FullMessage:  expectedMessage,
			},
			wantOK: false,
		},
		{
			name:  "IPv6 unspecified address",
			value: "::",
			path:  "server.host",
			wantFinding: &models.Finding{
				Value:        "::",
				Path:         "server.host",
				Level:        models.LevelMedium,
				ShortMessage: "открытый 0.0.0.0",
				FullMessage:  expectedMessage,
			},
			wantOK: false,
		},
		{
			name:        "IPv4 loopback",
			value:       "127.0.0.1",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "IPv6 loopback",
			value:       "::1",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "specific IPv4 address",
			value:       "192.168.1.10",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "specific public IPv4 address",
			value:       "8.8.8.8",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "specific IPv6 address",
			value:       "2001:db8::1",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "hostname",
			value:       "example.com",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "localhost hostname",
			value:       "localhost",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "empty string",
			value:       "",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "invalid IPv4",
			value:       "999.999.999.999",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "invalid IPv6",
			value:       "2001:::1",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "IPv4 with port",
			value:       "0.0.0.0:8080",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "IPv6 with port",
			value:       "[::]:8080",
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},

		// GetFinding должен игнорировать значения, которые не являются string.
		{
			name:        "nil value",
			value:       nil,
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "integer value",
			value:       123,
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "boolean value",
			value:       true,
			path:        "server.host",
			wantFinding: nil,
			wantOK:      true,
		},
		{
			name:        "slice value",
			value:       []string{"0.0.0.0"},
			path:        "server.host",
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
