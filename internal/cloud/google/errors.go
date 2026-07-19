package google

import (
	"errors"

	"github.com/Metrix-Cyber/athar/internal/cloud"
)

// asAPIError unwraps to a *cloud.APIError when the failure came from the API
// rather than from transport or decoding.
func asAPIError(err error, target **cloud.APIError) bool {
	var e *cloud.APIError
	if errors.As(err, &e) {
		*target = e
		return true
	}
	return false
}
