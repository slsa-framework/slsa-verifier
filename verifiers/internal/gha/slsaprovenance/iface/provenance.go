package iface

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// Provenance represents provenance for a predicate type and build type.
type Provenance interface {
	// BuilderID returns the builder id in the predicate.
	BuilderID() (string, error)

	// BuildType returns the buildType.
	BuildType() (string, error)

	// SourceURI is the full URI (including tag) of the source material.
	SourceURI() (string, error)

	// TriggerURI is the full URI (including tag) of the configuration / trigger.
	TriggerURI() (string, error)

	// Subject is the list of intoto subjects in the provenance.
	Subjects() ([]intoto.Subject, error)

	// GetBranch retrieves the branch name of the source from the provenance.
	GetBranch() (string, error)

	// GetTag retrieves the tag of the source from the provenance.
	GetTag() (string, error)

	// Get workflow trigger path.
	GetBuildTriggerPath() (string, error)

	// Get system pararmeters.
	GetSystemParameters() (map[string]any, error)

	// Get build invocation ID.
	GetBuildInvocationID() (string, error)

	// Get build start time.
	GetBuildStartTime() (*time.Time, error)

	// Get build finish time.
	GetBuildFinishTime() (*time.Time, error)

	// Get number of resolved dependencies.
	GetNumberResolvedDependencies() (int, error)

	// GetWorkflowInputs retrieves the inputs from the provenance. Only succeeds for event
	// relevant event types (workflow_inputs).
	GetWorkflowInputs() (map[string]interface{}, error)
}
