SHELL := /bin/bash
OUTPUT_FORMAT = $(shell if [ "${GITHUB_ACTIONS}" == "true" ]; then echo "github"; else echo ""; fi)

.PHONY: help
help: ## Shows all targets and help from the Makefile (this message).
	@echo "SLSA Verifier Installer Action Makefile"
	@echo "Usage: make [COMMAND]"
	@echo ""
	@grep --no-filename -E '^([/a-z.A-Z0-9_%-]+:.*?|)##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = "(:.*?|)## ?"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2; \
			} else { \
				if (length($$2) > 0) { \
					printf "\n%s\n", $$2; \
				} \
			} \
		}'

node_modules/.installed: package.json package-lock.json
	npm ci
	touch node_modules/.installed


.PHONY: clean
clean: ## Deletes the dist/ and node_modules/ folders
	rm -rf dist node_modules

.PHONY: package
package: node_modules/.installed ## Builds the dist/ folder
	npm run package

.PHONY: bundle
bundle: node_modules/.installed ## Format and package the Action
	npm run bundle


.PHONY: all
all: node_modules/.installed ## Runs format, lint, test, and package
	npm run all

## Testing
#####################################################################

.PHONY: test
test: node_modules/.installed ## Runs jest testing suite
	npm run test

## Linting
#####################################################################

.PHONY: lint
lint: node_modules/.installed ## Runs eslint
	npm run lint

## Formatting
#####################################################################

.PHONY: format
format: node_modules/.installed ## Runs the prettier formatter
	npm run format:write
