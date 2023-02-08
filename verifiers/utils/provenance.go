package utils

import (
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func GetAsString(environment map[string]interface{}, field string) (string, error) {
	value, ok := environment[field]
	if !ok {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload,
			fmt.Sprintf("environment type for %s", field))
	}

	i, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s '%s'", serrors.ErrorInvalidDssePayload, "environment type string", field)
	}
	return i, nil
}
