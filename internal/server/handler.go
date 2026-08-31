package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"

	"web-config-parser/internal/app"
)

// errorResponse — единый формат ошибки в JSON-ответе.
type errorResponse struct {
	Error string `json:"error"`
}

// Handler инкапсулирует зависимости, нужные HTTP-обработчикам.
// Analyzer переиспользуется между запросами (предполагается, что он не хранит
// состояние конкретного конфига — состояние живёт в отдельном app.App на запрос).
type Handler struct {
	log          *logrus.Logger
	maxBodyBytes int64
}

// NewHandler создаёт Handler с уже собранным анализатором и логгером.
func NewHandler(log *logrus.Logger, maxBodyBytes int64) *Handler {
	return &Handler{
		log:          log,
		maxBodyBytes: maxBodyBytes,
	}
}

// Routes собирает http.Handler со всеми эндпоинтами сервера.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("POST /validate", h.handleValidate)
	return mux
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleValidate принимает конфиг в теле запроса и формат через query-параметр
// или заголовок, прогоняет через существующий Analyzer и отдаёт результат в JSON.
//
// Пример запроса:
//
//	curl -X POST 'http://localhost:8080/validate?format=json' \
//	     --data-binary @config.json
//
// Формат также можно передать заголовком X-Config-Format вместо query-параметра.
func (h *Handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = r.Header.Get("X-Config-Format")
	}
	configFormat := app.FileExtension(format)
	configApp := app.NewDefault(h.log)
	if _, ok := configApp.GetParser(configFormat); !ok {
		h.writeError(w, http.StatusBadRequest, "неподдерживаемый или не указанный параметр format")
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	defer r.Body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.writeError(w, http.StatusRequestEntityTooLarge, "размер конфига превышает допустимый лимит")
			return
		}
		h.log.WithError(err).Error("не удалось прочитать тело запроса")
		h.writeError(w, http.StatusBadRequest, "не удалось прочитать тело запроса")
		return
	}
	if len(data) == 0 {
		h.writeError(w, http.StatusBadRequest, "тело запроса пустое, ожидается содержимое конфига")
		return
	}

	reqID := r.Header.Get("X-Request-ID")
	source := "request-body"
	if reqID != "" {
		source = reqID
	}

	if err := configApp.Load(io.NopCloser(bytes.NewReader(data)), app.FileExtension(format), source); err != nil {
		h.log.WithError(err).Warn("ошибка при загрузке конфига из запроса")
		h.writeError(w, http.StatusUnprocessableEntity, "не удалось разобрать конфиг: "+err.Error())
		return
	}

	results, err := configApp.Validate()
	if err != nil {
		h.log.WithError(err).Error("ошибка при валидации конфига")
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка при анализе конфига")
		return
	}

	h.writeJSON(w, http.StatusOK, results)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.log.WithError(err).Error("не удалось записать JSON-ответ")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, errorResponse{Error: message})
}
