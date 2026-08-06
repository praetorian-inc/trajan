package gitlab

import (
	"errors"
	"fmt"
)

// Carries the status code so callers need not match on the body string.
type APIError struct {
	StatusCode int
	Body       string
}

// Callers and tests match on this exact format.
func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Body)
}

// No body-string fallback: doRequest always records the exact status code.
func IsPermissionError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 403
}

func IsNotFoundError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

// GitLab answers 410 for expired job logs.
func IsGoneError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 410
}
