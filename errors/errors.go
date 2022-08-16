package verification

import "errors"

var (
	ErrorInvalidDssePayload        = errors.New("invalid DSSE envelope payload")
	ErrorMismatchBranch            = errors.New("branch used to generate the binary does not match provenance")
	ErrorMismatchBuilderID         = errors.New("builderID does not match provenance")
	ErrorMismatchSource            = errors.New("source used to generate the binary does not match provenance")
	ErrorMismatchWorkflowInputs    = errors.New("workflow input does not match")
	ErrorMalformedURI              = errors.New("URI is malformed")
	ErrorMismatchTag               = errors.New("tag used to generate the binary does not match provenance")
	ErrorMismatchVersionedTag      = errors.New("tag used to generate the binary does not match provenance")
	ErrorInvalidSemver             = errors.New("invalid semantic version")
	ErrorRekorSearch               = errors.New("error searching rekor entries")
	ErrorMismatchHash              = errors.New("binary artifact hash does not match provenance subject")
	ErrorInvalidRef                = errors.New("invalid ref")
	ErrorUntrustedReusableWorkflow = errors.New("untrusted reusable workflow")
	ErrorNoValidRekorEntries       = errors.New("could not find a matching valid signature entry")
	ErrorVerifierNotSupported      = errors.New("no verifier support the builder")
	ErrorNotSupported              = errors.New("not supported")
	ErrorInvalidFormat             = errors.New("invalid format")
)
