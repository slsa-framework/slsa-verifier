package gha

import (
	"errors"
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/iface"
	slsav02 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v0.2"
	slsav1 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance/v1.0"
)

func verifyProvenanceMatchesCertificate(prov iface.Provenance, workflow *WorkflowIdentity) error {
	// See the generation at https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/provenance.js.
	// Verify systemParameters.
	switch typedProv := prov.(type) {
	case *slsav1.NpmCLIGithubActionsProvenance:
		if err := verifyNpmCLIGithubActionsV1SystemParameters(typedProv, workflow); err != nil {
			return err
		}
	default:
		if err := verifySystemParameters(typedProv, workflow); err != nil {
			return err
		}
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
	if err := verifyPublishAttestationSubjectDigestName(prov, "sha512"); err != nil {
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

func verifyPublishAttestationSubjectDigestName(prov iface.Provenance, digestName string) error {
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

func verifyBuildConfig(prov iface.Provenance, workflow *WorkflowIdentity) error {
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

func verifyResolvedDependencies(prov iface.Provenance) error {
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

func verifyMetadata(prov iface.Provenance, workflow *WorkflowIdentity) error {
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

func verifyCommonMetadata(prov iface.Provenance, workflow *WorkflowIdentity) error {
	// Verify build invocation ID.
	provInvocationID, err := prov.GetBuildInvocationID()
	if err != nil {
		return err
	}

	if provInvocationID != "" {
		// Verify runID and runAttempt.
		var provRunID string
		var provRunAttempt string
		switch prov.(type) {
		case *slsav1.NpmCLIGithubActionsProvenance:
			provenanceInvocationIDParts := strings.Split(strings.TrimPrefix(provInvocationID, "https://github.com/"), "/")
			lenParts := len(provenanceInvocationIDParts)
			if lenParts != 7 {
				return fmt.Errorf("%w: invalid invocation ID: %v", serrors.ErrorInvalidFormat, provInvocationID)
			}
			provRunID = provenanceInvocationIDParts[lenParts-3]
			provRunAttempt = provenanceInvocationIDParts[lenParts-1]
		default:
			provenanceInvocationIDParts := strings.Split(provInvocationID, "-")
			if len(provenanceInvocationIDParts) != 2 {
				return fmt.Errorf("%w: invalid invocation ID: %v", serrors.ErrorInvalidFormat, provInvocationID)
			}
			provRunID = provenanceInvocationIDParts[0]
			provRunAttempt = provenanceInvocationIDParts[1]
		}

		certRunID, certRunAttempt, err := getRunIDs(workflow)
		if err != nil {
			return err
		}

		if provRunID != certRunID {
			return fmt.Errorf("%w: run ID: '%v' != '%v'",
				serrors.ErrorMismatchCertificate, provRunID, certRunID)
		}
		if provRunAttempt != certRunAttempt {
			return fmt.Errorf("%w: run ID: '%v' != '%v'",
				serrors.ErrorMismatchCertificate, provRunAttempt, certRunAttempt)
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

func verifyV02Metadata(prov iface.Provenance) error {
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
	prov02, ok := prov.(slsav02.ProvenanceV02)
	if !ok {
		return nil
	}
	predicate := prov02.Predicate()

	if predicate.Metadata == nil {
		return nil
	}

	if predicate.Metadata.Reproducible {
		return fmt.Errorf("%w: reproducible: %v",
			serrors.ErrorNonVerifiableClaim,
			predicate.Metadata.Reproducible)
	}

	completeness := predicate.Metadata.Completeness
	if completeness.Parameters || completeness.Materials ||
		completeness.Environment {
		return fmt.Errorf("%w: completeness: %v",
			serrors.ErrorNonVerifiableClaim,
			completeness)
	}
	return nil
}

func verifyV02Parameters(prov iface.Provenance) error {
	// https://github.com/in-toto/in-toto-golang/blob/master/in_toto/slsa_provenance/v0.2/provenance.go
	prov02, ok := prov.(slsav02.ProvenanceV02)
	if !ok {
		return nil
	}
	predicate := prov02.Predicate()

	if predicate.Invocation.Parameters == nil {
		return nil
	}
	m, ok := predicate.Invocation.Parameters.(map[string]any)
	if !ok || len(m) > 0 {
		return fmt.Errorf("%w: parameters: %v",
			serrors.ErrorNonVerifiableClaim, predicate.Invocation.Parameters)
	}

	return nil
}

func verifyV02BuildConfig(prov iface.Provenance) error {
	// https://github.com/in-toto/in-toto-golang/blob/master/in_toto/slsa_provenance/v0.2/provenance.go
	prov02, ok := prov.(slsav02.ProvenanceV02)
	if !ok {
		return nil
	}
	predicate := prov02.Predicate()

	if predicate.BuildConfig == nil {
		return nil
	}
	m, ok := predicate.BuildConfig.(map[string]any)
	if !ok || len(m) > 0 {
		return fmt.Errorf("%w: buildConfig: %v",
			serrors.ErrorNonVerifiableClaim, predicate.BuildConfig)
	}

	return nil
}

func verifyNpmCLIGithubActionsV1SystemParameters(prov iface.Provenance, workflow *WorkflowIdentity) error {
	prov, ok := prov.(*slsav1.NpmCLIGithubActionsProvenance)
	if !ok {
		return nil
	}
	sysParams, err := prov.GetSystemParameters()
	if err != nil {
		return err
	}
	githubParams, ok := sysParams["github"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidFormat, "github parameters")
	}
	// Verify that the parameters contain only fields we are able to verify
	// and that the values match the certificate.
	supportedNames := map[string]*string{
		"event_name":          &workflow.BuildTrigger,
		"repository_id":       workflow.SourceID,
		"repository_owner_id": workflow.SourceOwnerID,
	}
	for k := range githubParams {
		certValue, ok := supportedNames[k]
		if !ok {
			return fmt.Errorf("%w: unknown '%s' parameter", serrors.ErrorMismatchCertificate, k)
		}
		if err := verifySystemParameter(githubParams, k, certValue); err != nil {
			return err
		}
	}
	return nil
}

func verifySystemParameters(prov iface.Provenance, workflow *WorkflowIdentity) error {
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
	// NOTE: GITHUB_WORKFLOW_REF does not include the server url or leading '/'
	workflowPath := strings.TrimLeft(workflow.SubjectWorkflow.Path, "/")
	if err := verifySystemParameter(sysParams, "GITHUB_WORKFLOW_REF", &workflowPath); err != nil {
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
	if !common.Exists(params, "GITHUB_RUN_ID") && !common.Exists(params, "GITHUB_RUN_ATTEMPT") {
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
	if !common.Exists(params, name) {
		return nil
	}
	// Provenance contains the field, we must verify it.
	provValue, err := common.GetAsString(params, name)
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
