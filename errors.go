package rbac

import (
	"net/http"

	"github.com/pkg/errors"
)

// AuthErrorInterface represents an error with an associated, suggested HTTP status code and internal error code.
// Not directly used by this package but is exported to aid consumer packages testing against errors from this package.
type AuthErrorInterface interface {
	Code() int32
	Error() string
	StatusCode() int32
	StackTrace() errors.StackTrace
}

// authError represents an error with an associated HTTP status code.
// Implements default error interface.
type authError struct {
	err    error
	code   int32
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

// Error Codes for identifying error types.
const (
	CodeErrQueryMarshal   = 4001
	CodeErrQueryDocType   = 4002
	CodeErrAuthentication = 4011
	CodeErrRoles          = 4031
	CodeErrContract       = 4032
	CodeErrQuery          = 4033
)

// errAuthentication for authentication errors (user could not be authenticated).
func errAuthentication(err error) authError {
	err = errors.Wrap(err, "user authentication failed")

	return authError{
		err:    err,
		code:   CodeErrAuthentication,
		status: http.StatusUnauthorized,
	}
}

// errRoles error.
func errRoles(role string) authError {
	err := errors.Errorf("user roles not found. `%v` attribute does not exist on identity", role)

	return authError{
		err:    err,
		code:   CodeErrRoles,
		status: http.StatusForbidden,
	}
}

// errContract error.
func errContract() authError {
	err := errors.New("user doesn't have permission to invoke this contract")

	return authError{
		err:    err,
		code:   CodeErrContract,
		status: http.StatusForbidden,
	}
}

// errQuery error.
func errQuery(res string) authError {
	err := errors.Errorf("user doesn't have permission to query %v records", res)

	return authError{
		err:    err,
		code:   CodeErrQuery,
		status: http.StatusForbidden,
	}
}

// errQueryMarshal error.
func errQueryMarshal(err error) authError {
	err = errors.Wrap(err, "could not marshal query")

	return authError{
		err:    err,
		code:   CodeErrQueryMarshal,
		status: http.StatusBadRequest,
	}
}

// errQueryDocType error.
func errQueryDocType() authError {
	err := errors.New("docType not found in query, did you include it at the root?")

	return authError{
		err:    err,
		code:   CodeErrQueryDocType,
		status: http.StatusBadRequest,
	}
}

// errMarshal error.
func errMarshal(err error) authError {
	err = errors.Wrap(err, "Marshal failed")

	return authError{
		err:    err,
		code:   CodeErrQueryDocType,
		status: http.StatusBadRequest,
	}
}
