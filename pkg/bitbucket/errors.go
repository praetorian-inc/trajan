package bitbucket

import (
	"errors"
	"fmt"
)

// APIError represents a non-2xx HTTP response from the Bitbucket API.
// It carries the status code and response details so callers can inspect
// the specific error condition without string parsing.
type APIError struct {
	StatusCode int
	Message    string
	Detail     string
	Body       string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// IsPermissionError reports whether err (or any error in its chain)
// is a 403 Forbidden response from the Bitbucket API.
func IsPermissionError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 403
}

// IsNotFoundError reports whether err (or any error in its chain)
// is a 404 Not Found response from the Bitbucket API.
func IsNotFoundError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

// IsGoneError reports whether err (or any error in its chain)
// is a 410 Gone response from the Bitbucket API.
func IsGoneError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 410
}
