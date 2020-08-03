package rbac

import (
	"net/http"

	"github.com/pkg/errors"
)

// AuthErrorInterface represents an error with an associated, suggested HTTP status code and internal error code.
// It is not directly used by this package but is exported to aid consumer packages testing against errors from this package.
type AuthErrorInterface interface {
	Code() int32
	Error() string
	StatusCode() int32
	StackTrace() errors.StackTrace
}

// authError represents an error with an associated HTTP status code.
// Implements default error interface.
type authError struct {
	code   int32
	err    error
	status int32
}

// Error allows Error to satisfy the default error interface.
func (e authError) Error() string {
	return e.err.Error()
}

// StackTrace returns the error stacktrace and satisfies the errors.Stacktrace interface.
func (e authError) StackTrace() errors.StackTrace {
	type stackTracer interface {
		StackTrace() errors.StackTrace
	}
	if err, ok := e.err.(stackTracer); ok && err != nil {
		return err.StackTrace()
	}
	return nil
}

func (e authError) Code() int32 {
	return e.code
}

// StatusCode returns the suggest http status code.
func (e authError) StatusCode() int32 {
	return e.status
}

// errAuthentication for authentication errors (user could not be authenticated).
func errAuthentication(err error) authError {
	err = errors.Wrap(err, "User authentication failed")
	return authError{
		err:    err,
		code:   4011,
		status: http.StatusUnauthorized,
	}
}

// errRoles error.
func errRoles(role string) authError {
	err := errors.Errorf("User roles not found. `%v` does not exist on identity", role)
	return authError{
		err:    err,
		code:   4031,
		status: http.StatusForbidden,
	}
}

// errContract error.
func errContract() authError {
	err := errors.New("User doesn't have permission to invoke this function")
	return authError{
		err:    err,
		code:   4032,
		status: http.StatusForbidden,
	}
}
