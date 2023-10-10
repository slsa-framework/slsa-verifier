package common

import (
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// GetAsString returns the value in the given map as a string.
func GetAsString(m map[string]any, field string) (string, error) {
	value, ok := m[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("type for %s", field))
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s '%s'", serrors.ErrorInvalidDssePayload, "type string", field)
	}
	return i, nil
}
