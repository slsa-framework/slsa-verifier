package utils

import (
	"encoding/base64"
	"fmt"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func PayloadFromEnvelope(env *dsselib.Envelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: empty payload", serrors.ErrorInvalidFormat)
	}
	return payload, nil
}

func DecodeSignature(s string) ([]byte, error) {
	var errs []error
	// First try the std decoding.
	rsig, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	// If std decoding failed, try URL decoding.
	// We try both because we encountered decoding failures
	// during our tests. The DSSE documentation does not prescribe
	// which encoding to use: `Either standard or URL-safe encoding is allowed`.
	// https://github.com/secure-systems-lab/dsse/blob/27ce241dec575998dee8967c3c76d4edd5d6ee73/envelope.md#standard-json-envelope.
	rsig, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	return nil, fmt.Errorf("%w: %v", serrors.ErrorInvalidEncoding, errs)
}
