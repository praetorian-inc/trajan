package gitlab

import (
	"errors"
	"fmt"
)

// APIError represents a non-2xx HTTP response from the GitLab API.
// It carries the status code and raw body so callers can inspect
// the specific error condition without string parsing.
type APIError struct {
	StatusCode int
	Body       string
}

// Error implements the error interface.
// Format is identical to the previous fmt.Errorf string so existing
// error messages and tests that check err.Error() are unaffected.
func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Body)
}

// IsPermissionError reports whether err (or any error in its chain)
// is a 403 Forbidden response from the GitLab API.
//
// The previous isPermissionError also matched the string "Forbidden" as a
// fallback. That fallback is intentionally dropped: doRequest always encodes
// the exact HTTP status code into APIError.StatusCode, making body-string
// matching redundant.
func IsPermissionError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 403
}

// IsNotFoundError reports whether err (or any error in its chain)
// is a 404 Not Found response from the GitLab API.
func IsNotFoundError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

// IsGoneError reports whether err (or any error in its chain)
// is a 410 Gone response from the GitLab API (e.g. expired job logs).
func IsGoneError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 410
}
