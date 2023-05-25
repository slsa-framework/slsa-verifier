package gha

import (
	"errors"
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"

	// Load provenance types.
	slsav02 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v0.2"
	_ "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
)

func verifyProvenanceMatchesCertificate(prov slsaprovenance.Provenance, workflow *WorkflowIdentity) error {
	// See the generation at https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/provenance.js.
	// Verify systemParameters.
	if err := verifySystemParameters(prov, workflow); err != nil {
		return err
	}

	// Verify v0.2 parameters.
	if err := verifyV02Parameters(prov); err != nil {
		return err
	}

	// Verify metadata.
	if err := verifyMetadata(prov, workflow); err != nil {
		return err
	}

	// Verify subjects.
	if err := verifySubjectDigestName(prov, "sha512"); err != nil {
		return err
	}

	// Verify trigger config.
	if err := verifyBuildConfig(prov, workflow); err != nil {
		return err
	}

	// Verify resolved dependencies.
	if err := verifyResolvedDependencies(prov); err != nil {
		return err
	}

	// Verify v0.2 build config.
	if err := verifyV02BuildConfig(prov); err != nil {
		return err
	}

	// Additional fields can only be present in fields
	// defined as interface{}. We already verified buildConfig,
	// parameters and environment for v0.2.
	// In addition, fields not defined in the structures will cause an error
	// because we use stric unmarshaling in slsaprovenance.go.
	// TODO(#571): add tests for additional fields in the provenance.

	// Other fields such as material and config source URI / sha are verified
	// as part of the common verification.

	// TODO(#566): verify fields for v1.0 provenance.

	return nil
}

func verifySubjectDigestName(prov slsaprovenance.Provenance, digestName string) error {
	subjects, err := prov.Subjects()
	if err != nil {
		return err
	}

	if len(subjects) != 1 {
		return fmt.Errorf("%w: invalid number of digests: %v",
			serrors.ErrorNonVerifiableClaim, subjects)
	}

	_, ok := subjects[0].Digest[digestName]
	if !ok {
		return fmt.Errorf("%w: digest '%s' not present",
			serrors.ErrorNonVerifiableClaim, digestName)
	}
	return nil
}

func verifyBuildConfig(prov slsaprovenance.Provenance, workflow *WorkflowIdentity) error {
	triggerPath, err := prov.GetBuildTriggerPath()
	if err != nil {
		// If the field is not available in the provenance,
		// we can safely skip the verification against the certificate.
		if errors.Is(err, serrors.ErrorNotPresent) {
			return nil
		}
		return err
	}

	return equalCertificateValue(workflow.BuildConfigPath, triggerPath, "trigger workflow")
}

func verifyResolvedDependencies(prov slsaprovenance.Provenance) error {
	n, err := prov.GetNumberResolvedDependencies()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: unexpected number of resolved dependencies: %v",
			serrors.ErrorNonVerifiableClaim, n)
	}
	return nil
}

func verifyMetadata(prov slsaprovenance.Provenance, workflow *WorkflowIdentity) error {
	if err := verifyCommonMetadata(prov, workflow); err != nil {
		return err
	}

	// Verify v0.2 claims.
	if err := verifyV02Metadata(prov); err != nil {
		return err
	}

	// TODO(#566): verify fields for v1.0 provenance

	return nil
}

func verifyCommonMetadata(prov slsaprovenance.Provenance, workflow *WorkflowIdentity) error {
	// Verify build invocation ID.
	invocationID, err := prov.GetBuildInvocationID()
	if err != nil {
		return err
	}

	runID, runAttempt, err := getRunIDs(workflow)
	if err != nil {
		return err
	}

	// Only verify a non-empty buildID claim.
	if invocationID != "" {
		expectedID := fmt.Sprintf("%v-%v", runID, runAttempt)
		if invocationID != expectedID {
			return fmt.Errorf("%w: invocation ID: '%v' != '%v'",
				serrors.ErrorMismatchCertificate, invocationID,
				expectedID)
		}
	}

	// Verify start time.
	startTime, err := prov.GetBuildStartTime()
	if err != nil {
		return err
	}
	if startTime != nil {
		return fmt.Errorf("%w: build start time: %v",
			serrors.ErrorNonVerifiableClaim, *startTime)
	}

	// Verify finish time.
	finishTime, err := prov.GetBuildFinishTime()
	if err != nil {
		return err
	}
	if finishTime != nil {
		return fmt.Errorf("%w: build finish time: %v",
			serrors.ErrorNonVerifiableClaim, *finishTime)
	}
	return nil
}

func verifyV02Metadata(prov slsaprovenance.Provenance) error {
	// https://github.com/in-toto/in-toto-golang/blob/master/in_toto/slsa_provenance/v0.2/provenance.go
	/*
		v0.2:
			"buildInvocationId": "4757060009-1",
			"completeness": {
				"parameters": false,
				"environment": false,
				"materials": false
			},
			"reproducible": false
	*/
	prov02, ok := prov.(*slsav02.ProvenanceV02)
	if !ok {
		return nil
	}
	if prov02.Predicate.Metadata == nil {
		return nil
	}

	if prov02.Predicate.Metadata.Reproducible {
		return fmt.Errorf("%w: reproducible: %v",
			serrors.ErrorNonVerifiableClaim,
			prov02.Predicate.Metadata.Reproducible)
	}

	completeness := prov02.Predicate.Metadata.Completeness
	if completeness.Parameters || completeness.Materials ||
		completeness.Environment {
		return fmt.Errorf("%w: completeness: %v",
			serrors.ErrorNonVerifiableClaim,
			completeness)
	}
	return nil
}

func verifyV02Parameters(prov slsaprovenance.Provenance) error {
	// https://github.com/in-toto/in-toto-golang/blob/master/in_toto/slsa_provenance/v0.2/provenance.go
	prov02, ok := prov.(*slsav02.ProvenanceV02)
	if !ok {
		return nil
	}
	if prov02.Predicate.Invocation.Parameters == nil {
		return nil
	}
	m, ok := prov02.Predicate.Invocation.Parameters.(map[string]any)
	if !ok || len(m) > 0 {
		return fmt.Errorf("%w: parameters: %v",
			serrors.ErrorNonVerifiableClaim, prov02.Predicate.Invocation.Parameters)
	}

	return nil
}

func verifyV02BuildConfig(prov slsaprovenance.Provenance) error {
	// https://github.com/in-toto/in-toto-golang/blob/master/in_toto/slsa_provenance/v0.2/provenance.go
	prov02, ok := prov.(*slsav02.ProvenanceV02)
	if !ok {
		return nil
	}

	if prov02.Predicate.BuildConfig == nil {
		return nil
	}
	m, ok := prov02.Predicate.BuildConfig.(map[string]any)
	if !ok || len(m) > 0 {
		return fmt.Errorf("%w: buildConfig: %v",
			serrors.ErrorNonVerifiableClaim, prov02.Predicate.BuildConfig)
	}

	return nil
}

func verifySystemParameters(prov slsaprovenance.Provenance, workflow *WorkflowIdentity) error {
	/*
		"environment": {
			"GITHUB_EVENT_NAME": "workflow_dispatch",
			"GITHUB_REF": "refs/heads/main",
			"GITHUB_REPOSITORY": "laurentsimon/provenance-npm-test",
			"GITHUB_REPOSITORY_ID": "602223945",
			"GITHUB_REPOSITORY_OWNER_ID": "64505099",
			"GITHUB_RUN_ATTEMPT": "1",
			"GITHUB_RUN_ID": "4757060009",
			"GITHUB_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14",
			"GITHUB_WORKFLOW_REF": "laurentsimon/provenance-npm-test/.github/workflows/release.yml@refs/heads/main",
			"GITHUB_WORKFLOW_SHA": "b38894f2dda4355ea5606fccb166e61565e12a14"
		  }
	*/
	sysParams, err := prov.GetSystemParameters()
	if err != nil {
		return err
	}
	// Verify that the parameters contain only fields we are able to verify.
	// There are 10 fields to verify.
	supportedNames := map[string]bool{
		"GITHUB_EVENT_NAME":          true,
		"GITHUB_REF":                 true,
		"GITHUB_REPOSITORY":          true,
		"GITHUB_REPOSITORY_ID":       true,
		"GITHUB_REPOSITORY_OWNER_ID": true,
		"GITHUB_RUN_ATTEMPT":         true,
		"GITHUB_RUN_ID":              true,
		"GITHUB_SHA":                 true,
		"GITHUB_WORKFLOW_REF":        true,
		"GITHUB_WORKFLOW_SHA":        true,
	}

	for k := range sysParams {
		if !supportedNames[k] {
			return fmt.Errorf("%w: unknown '%s' parameter", serrors.ErrorMismatchCertificate, k)
		}
	}

	// 1. GITHUB_EVENT_NAME.
	if err := verifySystemParameter(sysParams, "GITHUB_EVENT_NAME", &workflow.BuildTrigger); err != nil {
		return err
	}
	// 2. GITHUB_REPOSITORY
	if err := verifySystemParameter(sysParams, "GITHUB_REPOSITORY", &workflow.SourceRepository); err != nil {
		return err
	}
	// 3. GITHUB_REF
	if err := verifySystemParameter(sysParams, "GITHUB_REF", workflow.SourceRef); err != nil {
		return err
	}
	// 4. GITHUB_REPOSITORY_ID
	if err := verifySystemParameter(sysParams, "GITHUB_REPOSITORY_ID", workflow.SourceID); err != nil {
		return err
	}
	// 5. GITHUB_REPOSITORY_OWNER_ID
	if err := verifySystemParameter(sysParams, "GITHUB_REPOSITORY_OWNER_ID", workflow.SourceOwnerID); err != nil {
		return err
	}
	// 6. GITHUB_REPOSITORY_SHA
	if err := verifySystemParameter(sysParams, "GITHUB_SHA", &workflow.SourceSha1); err != nil {
		return err
	}
	// 7. GITHUB_WORKFLOW_REF
	if err := verifySystemParameter(sysParams, "GITHUB_WORKFLOW_REF", &workflow.SubjectWorkflowRef); err != nil {
		return err
	}
	// 8. GITHUB_WORKFLOW_SHA
	if err := verifySystemParameter(sysParams, "GITHUB_WORKFLOW_SHA", workflow.SubjectSha1); err != nil {
		return err
	}

	// 9-10. GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT
	if err := verifySystemRun(sysParams, workflow); err != nil {
		return err
	}
	return nil
}

func getRunIDs(workflow *WorkflowIdentity) (string, string, error) {
	if workflow == nil {
		return "", "", fmt.Errorf("%w: empty workflow", serrors.ErrorInvalidFormat)
	}
	if workflow.RunID == nil {
		return "", "", nil
	}
	parts := strings.Split(*workflow.RunID, "/")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, *workflow.RunID)
	}
	return parts[0], parts[2], nil
}

func verifySystemRun(params map[string]any, workflow *WorkflowIdentity) error {
	// Verify only if the values are provided in the provenance.
	if !slsaprovenance.Exists(params, "GITHUB_RUN_ID") && !slsaprovenance.Exists(params, "GITHUB_RUN_ATTEMPT") {
		return nil
	}
	// The certificate contains runID as '4757060009/attempts/1'.
	if workflow.RunID == nil {
		return fmt.Errorf("%w: empty certificate value to verify 'GITHUB_RUN_*'",
			serrors.ErrorMismatchCertificate)
	}

	runID, runAttempt, err := getRunIDs(workflow)
	if err != nil {
		return err
	}

	if err := verifySystemParameter(params, "GITHUB_RUN_ID", &runID); err != nil {
		return err
	}
	if err := verifySystemParameter(params, "GITHUB_RUN_ATTEMPT", &runAttempt); err != nil {
		return err
	}

	return nil
}

func verifySystemParameter(params map[string]any, name string, certValue *string) error {
	// If the provenance does not contain an env variable.
	if !slsaprovenance.Exists(params, name) {
		return nil
	}
	// Provenance contains the field, we must verify it.
	provValue, err := slsaprovenance.GetAsString(params, name)
	if err != nil {
		return err
	}
	// The certificate must have the value. Old Fulcio certs are not
	// supported.
	return equalCertificateValue(certValue, provValue, name)
}

func equalCertificateValue(expected *string, actual, logName string) error {
	if expected == nil {
		return fmt.Errorf("%w: empty certificate value to verify '%s'",
			serrors.ErrorMismatchCertificate, logName)
	}

	if actual != *expected {
		return fmt.Errorf("%w: %s: '%s' != '%s'", serrors.ErrorMismatchCertificate,
			logName, actual, *expected)
	}
	return nil
}
