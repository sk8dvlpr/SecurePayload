package securepayload

import "fmt"

// Error membawa status HTTP-style dan konteks debug (pesan dalam Bahasa Indonesia).
type Error struct {
	Status  int
	Message string
	Context map[string]interface{}
}

func (e *Error) Error() string {
	return e.Message
}

func newError(status int, message string, ctx map[string]interface{}) *Error {
	if ctx == nil {
		ctx = map[string]interface{}{}
	}
	return &Error{Status: status, Message: message, Context: ctx}
}

func errorf(status int, format string, args ...interface{}) *Error {
	return newError(status, fmt.Sprintf(format, args...), nil)
}
