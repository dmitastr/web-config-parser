package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	"web-config-parser/internal/analyzers"
	"web-config-parser/internal/logging"
	"web-config-parser/internal/server"
)

// Значения по умолчанию для флагов/переменных окружения.
const (
	defaultHost            = "127.0.0.1"
	defaultPort            = 8080
	defaultReadTimeout     = 5 * time.Second
	defaultWriteTimeout    = 10 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 10 * time.Second
	defaultMaxBodyBytes    = 5 * 1024 * 1024 // 5 MiB
	defaultLogLevel        = "info"
)

// serverOptions собирает итоговые параметры запуска: флаг имеет приоритет
// над переменной окружения, если указаны оба.
type serverOptions struct {
	host            string
	port            int
	readTimeout     time.Duration
	writeTimeout    time.Duration
	idleTimeout     time.Duration
	shutdownTimeout time.Duration
	maxBodyBytes    int64
	logLevel        string
}

func main() {
	opts := parseOptions()

	log := logging.New(parseLogLevel(opts.logLevel))

	analyzer := analyzers.NewConfigAnalyzer(
		&analyzers.HostAnalyzer{},
		&analyzers.PlaintextSecretAnalyzer{},
		&analyzers.DebugModeAnalyzer{},
		&analyzers.OldCipherAlgoAnalyzer{},
		&analyzers.TLSDisableAnalyzer{},
	)

	handler := server.NewHandler(analyzer, log, opts.maxBodyBytes)

	srv := server.New(server.Config{
		Host:            opts.host,
		Port:            opts.port,
		ReadTimeout:     opts.readTimeout,
		WriteTimeout:    opts.writeTimeout,
		IdleTimeout:     opts.idleTimeout,
		ShutdownTimeout: opts.shutdownTimeout,
		MaxBodyBytes:    opts.maxBodyBytes,
	}, handler.Routes(), log)

	// SIGINT/SIGTERM отменяют контекст — Server.Run перехватывает это
	// и выполняет graceful shutdown с ограничением по времени.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		log.WithError(err).Fatal("сервер завершился с ошибкой")
	}
}

// parseOptions разбирает флаги командной строки, используя переменные
// окружения как значения по умолчанию (флаг всегда имеет приоритет).
func parseOptions() serverOptions {
	var opts serverOptions

	flag.StringVar(&opts.host, "host", envOrDefault("SERVER_HOST", defaultHost),
		"адрес интерфейса для прослушивания (env: SERVER_HOST)")
	flag.IntVar(&opts.port, "port", envOrDefaultInt("SERVER_PORT", defaultPort),
		"порт для прослушивания (env: SERVER_PORT)")
	flag.DurationVar(&opts.readTimeout, "read-timeout", envOrDefaultDuration("SERVER_READ_TIMEOUT", defaultReadTimeout),
		"таймаут на чтение запроса (env: SERVER_READ_TIMEOUT)")
	flag.DurationVar(&opts.writeTimeout, "write-timeout", envOrDefaultDuration("SERVER_WRITE_TIMEOUT", defaultWriteTimeout),
		"таймаут на запись ответа (env: SERVER_WRITE_TIMEOUT)")
	flag.DurationVar(&opts.idleTimeout, "idle-timeout", envOrDefaultDuration("SERVER_IDLE_TIMEOUT", defaultIdleTimeout),
		"таймаут простоя keep-alive соединения (env: SERVER_IDLE_TIMEOUT)")
	flag.DurationVar(&opts.shutdownTimeout, "shutdown-timeout", envOrDefaultDuration("SERVER_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		"максимальное время ожидания graceful shutdown (env: SERVER_SHUTDOWN_TIMEOUT)")
	flag.Int64Var(&opts.maxBodyBytes, "max-body-bytes", envOrDefaultInt64("SERVER_MAX_BODY_BYTES", defaultMaxBodyBytes),
		"максимальный размер тела запроса в байтах (env: SERVER_MAX_BODY_BYTES)")
	flag.StringVar(&opts.logLevel, "log-level", envOrDefault("SERVER_LOG_LEVEL", defaultLogLevel),
		"уровень логирования: debug|info|warn|error (env: SERVER_LOG_LEVEL)")

	flag.Parse()

	return opts
}

func parseLogLevel(level string) logrus.Level {
	parsed, err := logrus.ParseLevel(level)
	if err != nil {
		return logrus.InfoLevel
	}
	return parsed
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return fallback
}

func envOrDefaultInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			return parsed
		}
	}
	return fallback
}

func envOrDefaultDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			return parsed
		}
	}
	return fallback
}
