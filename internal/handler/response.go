package handler

import (
	"authservice/internal/errors"
	"encoding/json"
	"log/slog"
	"net/http"
)

type Response struct {
	Success bool           `json:"success"`
	Data    interface{}    `json:"data,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func WriteError(w http.ResponseWriter, err error) {

	appErr, isAppError := errors.IsAppError(err)

	var statusCode int
	var errorResponse ErrorResponse

	if isAppError {
		statusCode = appErr.GetHTTPStatus()
		errorResponse = ErrorResponse{
			Type:    string(appErr.Type),
			Message: appErr.Message,
		}
	} else {
		statusCode = http.StatusInternalServerError
		errorResponse = ErrorResponse{
			Type:    string(errors.ErrorTypeInternal),
			Message: "Internal server error",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := Response{
		Success: false,
		Error:   &errorResponse,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode error response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func WriteSuccess(w http.ResponseWriter, data any) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := Response{
		Success: true,
		Data:    data,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func WriteTypeError(w http.ResponseWriter, typeError errors.ErrorType, message string) {
	err := errors.NewError(typeError, message, nil)
	WriteError(w, err)
}
