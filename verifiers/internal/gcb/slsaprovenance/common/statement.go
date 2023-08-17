package common

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

var intotoStatements = map[string]bool{
	intoto.StatementInTotoV01:         true,
	"https://in-toto.io/Statement/v1": true,
}

func ValidateStatementTypes(statementType, predicateType, expectedPredicateType string) error {
	// Validate the intoto type.
	if _, exists := intotoStatements[statementType]; !exists {
		return fmt.Errorf("%w: expected statement header type on of '%v', got '%s'",
			serrors.ErrorInvalidDssePayload, intotoStatements, statementType)
	}

	// Validate the predicate type.
	if predicateType != expectedPredicateType {
		return fmt.Errorf("%w: expected statement predicate type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, expectedPredicateType, predicateType)
	}
	return nil
}
