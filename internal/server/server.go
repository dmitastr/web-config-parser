package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Config описывает параметры запуска HTTP-сервера.
type Config struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	MaxBodyBytes    int64
}

// Server — тонкая обёртка над http.Server с управляемым запуском/остановкой.
type Server struct {
	httpServer      *http.Server
	shutdownTimeout time.Duration
	log             *logrus.Logger
}

// New собирает Server поверх переданного http.Handler (обычно h.Routes()).
func New(cfg Config, handler http.Handler, log *logrus.Logger) *Server {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))

	return &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
		shutdownTimeout: cfg.ShutdownTimeout,
		log:             log,
	}
}

// Run запускает сервер и блокируется до отмены переданного контекста,
// после чего выполняет graceful shutdown с ограничением по времени.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		s.log.Infof("HTTP-сервер запущен на %s", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("сервер завершился с ошибкой: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err

	case <-ctx.Done():
		s.log.Info("получен сигнал остановки, начинаю graceful shutdown")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("ошибка при graceful shutdown: %w", err)
		}

		s.log.Info("сервер остановлен")
		return nil
	}
}
