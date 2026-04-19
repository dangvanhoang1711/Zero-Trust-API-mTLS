package auth

import "net/http"

type AuthError struct {
	HTTPStatus int
	Message    string
}

func (e *AuthError) Error() string {
	return e.Message
}

func unauthorized(msg string) *AuthError {
	return &AuthError{HTTPStatus: http.StatusUnauthorized, Message: msg}
}

func forbidden(msg string) *AuthError {
	return &AuthError{HTTPStatus: http.StatusForbidden, Message: msg}
}
