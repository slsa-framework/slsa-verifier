package verification

import "errors"

var (
	ErrorInvalidDssePayload        = errors.New("invalid DSSE envelope payload")
	ErrorMismatchBranch            = errors.New("branch used to generate the binary does not match provenance")
	ErrorMismatchRepository        = errors.New("repository used to generate the binary does not match provenance")
	ErrorMismatchTag               = errors.New("tag used to generate the binary does not match provenance")
	ErrorMismatchVersionedTag      = errors.New("tag used to generate the binary does not match provenance")
	ErrorInvalidSemver             = errors.New("invalid semantic version")
	ErrorRekorSearch               = errors.New("error searching rekor entries")
	errorMismatchHash              = errors.New("binary artifact hash does not match provenance subject")
	errorInvalidRef                = errors.New("invalid ref")
	errorMalformedWorkflowURI      = errors.New("malformed URI for workflow")
	ErrorUntrustedReusableWorkflow = errors.New("untrusted reusable workflow")
	ErrorNoValidRekorEntries       = errors.New("could not find a matching valid signature entry")
)
