package models

import "time"

// Config — корневая структура конфигурации веб-приложения
type Config struct {
	App      *AppConfig     `json:"app" yaml:"app"`
	Server   ServerConfig   `json:"server" yaml:"server"`
	Database DatabaseConfig `json:"database" yaml:"database"`
	Redis    *RedisConfig   `json:"redis,omitempty" yaml:"redis,omitempty"`
	Logging  LoggingConfig  `json:"logging" yaml:"logging"`
	CORS     *CORSConfig    `json:"cors,omitempty" yaml:"cors,omitempty"`
	Auth     AuthConfig     `json:"auth" yaml:"auth"`
}

// AppConfig — общие метаданные приложения
type AppConfig struct {
	Name    string `json:"name" yaml:"name"`
	Env     string `json:"env" yaml:"env"` // development | staging | production
	Debug   bool   `json:"debug" yaml:"debug"`
	Version string `json:"version" yaml:"version"`
}

// ServerConfig — параметры HTTP-сервера
type ServerConfig struct {
	Host         string        `json:"host" yaml:"host"`
	Port         int           `json:"port" yaml:"port"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	TLS          *TLSConfig    `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// TLSConfig — настройки TLS-соединения
type TLSConfig struct {
	Enabled      bool     `json:"enabled" yaml:"enabled"`
	CertFile     string   `json:"cert_file" yaml:"cert_file"`
	KeyFile      string   `json:"key_file" yaml:"key_file"`
	MinVersion   string   `json:"min_version" yaml:"min_version"`
	CipherSuites []string `json:"cipher_suites,omitempty" yaml:"cipher_suites,omitempty"`
}

// DatabaseConfig — подключение к БД
type DatabaseConfig struct {
	Driver          string        `json:"driver" yaml:"driver"`
	Host            string        `json:"host" yaml:"host"`
	Port            int           `json:"port" yaml:"port"`
	User            string        `json:"user" yaml:"user"`
	Password        string        `json:"password" yaml:"password"`
	Name            string        `json:"name" yaml:"name"`
	SSLMode         string        `json:"sslmode" yaml:"sslmode"`
	MaxOpenConns    int           `json:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

// RedisConfig — подключение к Redis (опционально, поэтому в Config это *RedisConfig)
type RedisConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	DB       int    `json:"db" yaml:"db"`
}

// LoggingConfig — настройки логирования
type LoggingConfig struct {
	Level  string `json:"level" yaml:"level"`   // debug | info | warn | error
	Format string `json:"format" yaml:"format"` // json | text
	Output string `json:"output" yaml:"output"` // stdout | stderr | путь к файлу
}

// CORSConfig — настройки CORS (опционально)
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods" yaml:"allowed_methods"`
	AllowCredentials bool     `json:"allow_credentials" yaml:"allow_credentials"`
}

// AuthConfig — параметры аутентификации/JWT
type AuthConfig struct {
	JWTSecret       string        `json:"jwt_secret" yaml:"jwt_secret"`
	JWTAlgorithm    string        `json:"jwt_algorithm" yaml:"jwt_algorithm"`
	AccessTokenTTL  time.Duration `json:"access_token_ttl" yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `json:"refresh_token_ttl" yaml:"refresh_token_ttl"`
}
