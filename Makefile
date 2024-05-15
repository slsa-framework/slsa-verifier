SHELL := /bin/bash
OUTPUT_FORMAT = $(shell if [ "${GITHUB_ACTIONS}" == "true" ]; then echo "github"; else echo ""; fi)

.PHONY: help
help: ## Shows all targets and help from the Makefile (this message).
	@echo "slsa-github-generator Makefile"
	@echo "Usage: make [COMMAND]"
	@echo ""
	@grep --no-filename -E '^([/a-z.A-Z0-9_%-]+:.*?|)##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = "(:.*?|)## ?"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2; \
			} else { \
				if (length($$2) > 0) { \
					printf "%s\n", $$2; \
				} \
			} \
		}'

node_modules/.installed: package.json package-lock.json
	npm ci
	touch node_modules/.installed

## Testing
#####################################################################

.PHONY: unit-test
unit-test: ## Runs all unit tests.
	@ # NOTE: go test builds packages even if there are no tests.
	@set -e;\
		go mod vendor; \
		extraargs=""; \
		if [ "$(OUTPUT_FORMAT)" == "github" ]; then \
			extraargs="-v"; \
		fi; \
		go test -mod=vendor $$extraeargs ./...

.PHONY: regression-test
regression-test: ## Runs all regression and unit tests.
	@ # NOTE: go test builds packages even if there are no tests.
	@set -e;\
		go mod vendor; \
		extraargs=""; \
		if [ "$(OUTPUT_FORMAT)" == "github" ]; then \
			extraargs="-v"; \
		fi; \
		go test -mod=vendor -tags=regression $$extraeargs -timeout=25m ./...

## Tools
#####################################################################

.PHONY: markdown-toc
markdown-toc: node_modules/.installed ## Runs markdown-toc on markdown files.
	@# NOTE: Do not include issue templates since they contain Front Matter.
	@# markdown-toc will update Front Matter even if there is no TOC in the file.
	@# See: https://github.com/jonschlinkert/markdown-toc/issues/151
	@set -euo pipefail; \
		md_files=$$( \
			find . -name '*.md' -type f \
				-not -iwholename '*/.git/*' \
				-not -iwholename '*/vendor/*' \
				-not -iwholename '*/node_modules/*' \
				-not -iwholename '*/.github/ISSUE_TEMPLATE/*' \
		); \
		for filename in $${md_files}; do \
			npm run markdown-toc "$${filename}"; \
		done;

## Linters
#####################################################################

.PHONY: lint
lint: golangci-lint eslint yamllint renovate-config-validator ## Run all linters.

.PHONY: golangci-lint
golangci-lint: ## Runs the golangci-lint linter.
	@set -e;\
		extraargs=""; \
		if [ "$(OUTPUT_FORMAT)" == "github" ]; then \
			extraargs="--out-format github-actions"; \
		fi; \
		golangci-lint run -c .golangci.yml ./... $$extraargs

.PHONY: eslint
eslint: ## Runs the eslint linter.
	make -C actions/installer lint

.PHONY: yamllint
yamllint: ## Runs the yamllint linter.
	@set -e;\
		extraargs=""; \
		if [ "$(OUTPUT_FORMAT)" == "github" ]; then \
			extraargs="-f github"; \
		fi; \
		yamllint -c .yamllint.yaml . $$extraargs

.PHONY: renovate-config-validator
renovate-config-validator: node_modules/.installed ## Runs renovate-config-validator
	@npm run renovate-config-validator
