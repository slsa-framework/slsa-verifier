package utils

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
)

func ParseBuilderID(id string, needVersion bool) (string, string, error) {
	parts := strings.Split(id, "@")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}

	if len(parts) == 1 && !needVersion {
		return parts[0], "", nil
	}

	return "", "", fmt.Errorf("%w: builderID: '%s'",
		serrors.ErrorInvalidFormat, id)
}
