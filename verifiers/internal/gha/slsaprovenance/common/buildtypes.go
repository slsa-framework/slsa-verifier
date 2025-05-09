package common

var (
	// BYOBBuildTypeV0 is the base buildType for BYOB delegated builders.
	BYOBBuildTypeV0 = "https://github.com/slsa-framework/slsa-github-generator/delegator-generic@v0"

	// ContainerBasedBuildTypeV01Draft is the buildType for the container-based builder.
	ContainerBasedBuildTypeV01Draft = "https://slsa.dev/container-based-build/v0.1?draft"

	// GoBuilderBuildTypeV1 is the buildType for the Go builder.
	GoBuilderBuildTypeV1 = "https://github.com/slsa-framework/slsa-github-generator/go@v1"

	// GenericGeneratorBuildTypeV1 is the buildType for the generic generator.
	GenericGeneratorBuildTypeV1 = "https://github.com/slsa-framework/slsa-github-generator/generic@v1"

	// ContainerGeneratorBuildTypeV1 is the buildType for the container generator.
	ContainerGeneratorBuildTypeV1 = "https://github.com/slsa-framework/slsa-github-generator/container@v1"

	// NpmCLIBuildTypeV1 is the buildType for provenance generated by the npm cli.
	NpmCLIBuildTypeV1 = "https://github.com/npm/cli/gha@v1"

	// NpmCLIBuildTypeV2 is the buildType for provenance generated by the npm cli.
	NpmCLIBuildTypeV2 = "https://github.com/npm/cli/gha/v2"

	// NpmCLIGithubActionsBuildTypeV1 is the buildType for provenance by the npm cli from GitHub Actions.
	NpmCLIGithubActionsBuildTypeV1 = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"

	GithubActionsBuildTypeV1 = "https://actions.github.io/buildtypes/workflow/v1"
)

// Legacy buildTypes.
var (
	// LegacyGoBuilderBuildTypeV1 is a legacy Go builder buildType.
	LegacyGoBuilderBuildTypeV1 = "https://github.com/slsa-framework/slsa-github-generator-go@v1"

	// LegacyBuilderBuildTypeV1 is a legacy generic build type for slsa-github-generator.
	LegacyBuilderBuildTypeV1 = "https://github.com/slsa-framework/slsa-github-generator@v1"
)
