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

func verifySubjectDigestName(prov iface.Provenance, digestName string) error {
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
		var expectedID string
		switch p := prov.(type) {
		case slsav1.ProvenanceV1:
			triggerURI, err := prov.TriggerURI()
			if err != nil {
				return err
			}
			parts := strings.SplitN(triggerURI, "@", 2)
			expectedID = fmt.Sprintf("%s/actions/runs/%s/attempts/%s", parts[0], runID, runAttempt)
		case slsav02.ProvenanceV02:
			expectedID = fmt.Sprintf("%v-%v", runID, runAttempt)
		default:
			return fmt.Errorf("%w: provenance type %v", serrors.ErrorInternal, p)
		}
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

func normalize(n string, isV1 bool) string {
	if isV1 {
		return strings.ToLower(n)
	}
	return "GITHUB_" + strings.ToUpper(n)
}

func verifySystemParameters(prov iface.Provenance, workflow *WorkflowIdentity) error {
	/*
				For v0.2 CLI:
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

				For v1 CLI:
				"github": {
					"event_name": "workflow_dispatch",
					"repository_id": "602223945",
					"repository_owner_id": "64505099"
		        }
	*/
	sysParams, err := prov.GetSystemParameters()
	if err != nil {
		return err
	}

	var supportedNames map[string]bool
	var isV1 bool
	switch p := prov.(type) {
	case slsav1.ProvenanceV1:
		// Validate the parameters: there should be a single "github" entry.
		if len(sysParams) > 1 {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "more than one entry in external parameters")
		}
		gh, ok := sysParams["github"]
		if !ok {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "workflow parameters type")
		}
		ghMap, ok := gh.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "system parameters github type")
		}
		// Set the map.
		sysParams = ghMap
		// Set the list of supported keys.
		// Verify that the parameters contain only fields we are able to verify.
		supportedNames = map[string]bool{
			normalize("event_name", true):          true,
			normalize("repository_id", true):       true,
			normalize("repository_owner_id", true): true,
		}
		isV1 = true

	case slsav02.ProvenanceV02:
		// Verify that the parameters contain only fields we are able to verify.
		// There are 10 fields to verify.
		supportedNames = map[string]bool{
			normalize("event_name", false):          true,
			normalize("ref", false):                 true,
			normalize("repository", false):          true,
			normalize("repository_id", false):       true,
			normalize("repository_owner_id", false): true,
			normalize("run_attempt", false):         true,
			normalize("run_id", false):              true,
			normalize("sha", false):                 true,
			normalize("workflow_ref", false):        true,
			normalize("workflow_sha", false):        true,
		}
		isV1 = false

	default:
		return fmt.Errorf("%w: unknown %v type", serrors.ErrorInternal, p)
	}

	for k := range sysParams {
		if !supportedNames[k] {
			return fmt.Errorf("%w: unknown '%s' parameter", serrors.ErrorMismatchCertificate, k)
		}
	}

	// 1. GITHUB_EVENT_NAME.
	if err := verifySystemParameter(sysParams, normalize("event_name", isV1), &workflow.BuildTrigger); err != nil {
		return err
	}
	// 2. GITHUB_REPOSITORY
	if err := verifySystemParameter(sysParams, normalize("repository", isV1), &workflow.SourceRepository); err != nil {
		return err
	}
	// 3. GITHUB_REF
	if err := verifySystemParameter(sysParams, normalize("ref", isV1), workflow.SourceRef); err != nil {
		return err
	}
	// 4. GITHUB_REPOSITORY_ID
	if err := verifySystemParameter(sysParams, normalize("repository_id", isV1), workflow.SourceID); err != nil {
		return err
	}
	// 5. GITHUB_REPOSITORY_OWNER_ID
	if err := verifySystemParameter(sysParams, normalize("repository_owner_id", isV1), workflow.SourceOwnerID); err != nil {
		return err
	}
	// 6. GITHUB_REPOSITORY_SHA
	if err := verifySystemParameter(sysParams, normalize("sha", isV1), &workflow.SourceSha1); err != nil {
		return err
	}
	// 7. GITHUB_WORKFLOW_REF
	// NOTE: GITHUB_WORKFLOW_REF does not include the server url or leading '/'
	workflowPath := strings.TrimLeft(workflow.SubjectWorkflow.Path, "/")
	if err := verifySystemParameter(sysParams, normalize("workflow_ref", isV1), &workflowPath); err != nil {
		return err
	}
	// 8. GITHUB_WORKFLOW_SHA
	if err := verifySystemParameter(sysParams, normalize("workflow_sha", isV1), workflow.SubjectSha1); err != nil {
		return err
	}

	// 9-10. GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT
	if err := verifySystemRun(sysParams, workflow, isV1); err != nil {
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

func verifySystemRun(params map[string]any, workflow *WorkflowIdentity, isV1 bool) error {
	// Verify only if the values are provided in the provenance.
	if !common.Exists(params, normalize("run_id", isV1)) && !common.Exists(params, normalize("run_attempt", isV1)) {
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

	if err := verifySystemParameter(params, normalize("run_id", isV1), &runID); err != nil {
		return err
	}
	if err := verifySystemParameter(params, normalize("run_attempt", isV1), &runAttempt); err != nil {
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
