package common

var trustedBuilderRepository = "https://github.com/slsa-framework/slsa-github-generator"

var (
	// GenericGeneratorBuilderID is the builder ID for the Generic Generator.
	GenericGeneratorBuilderID = trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml"
	// ContainerGeneratorBuilderID is the builder ID for the Container Generator.
	ContainerGeneratorBuilderID = trustedBuilderRepository + "/.github/workflows/generator_container_slsa3.yml"
	// GoBuilderID is the SLSA builder ID for the Go Builder.
	GoBuilderID = trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml"
	// ContainerBasedBuilderID is the SLSA builder ID for the Container-Based Builder.
	ContainerBasedBuilderID = trustedBuilderRepository + "/.github/workflows/builder_container-based_slsa3.yml"

	// NpmCLILegacyBuilderID is the legacy builder ID for the npm CLI.
	NpmCLILegacyBuilderID = "https://github.com/actions/runner"
	// NpmCLIHostedBuilderID is the builder ID for the npm CLI on Hosted GitHub Actions.
	NpmCLIHostedBuilderID = NpmCLILegacyBuilderID + "/github-hosted"
	// NpmCLISelfHostedBuilderID is the builder ID for the npm CLI on Self-hosted GitHub Actions.
	NpmCLISelfHostedBuilderID = NpmCLILegacyBuilderID + "/self-hosted"

	// GenericDelegatorBuilderID is the SLSA builder ID for the BYOB Generic Low-Permissions Delegated Builder.
	GenericDelegatorBuilderID = trustedBuilderRepository + "/.github/workflows/delegator_generic_slsa3.yml"
	// GenericLowPermsDelegatorBuilderID is the SLSA builder ID for the BYOB Generic Low-Permissions Delegated Builder.
	GenericLowPermsDelegatorBuilderID = trustedBuilderRepository + "/.github/workflows/delegator_lowperms-generic_slsa3.yml"

	// BCRReleaserBuilderID is the bcr reusable workflow that generates github attestations for a ruleset release.
	BCRReleaserBuilderID = "https://github.com/bazel-contrib/.github/.github/workflows/release_ruleset.yaml"
	// BCRPublisherBuilderID is the bcr reusable workflow that generates github attestations for BCR repository metadata.
	BCRPublisherBuilderID = "https://github.com/bazel-contrib/publish-to-bcr/.github/workflows/publish.yaml"
)
