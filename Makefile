# comwatch — Makefile
# Requires the .NET 8 SDK (https://dotnet.microsoft.com/download).
.DEFAULT_GOAL := help
DOTNET ?= dotnet

.PHONY: help build test selftest demo publish docker clean fmt

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the CLI (Release)
	$(DOTNET) build -c Release

test: ## Run the xUnit test suite
	$(DOTNET) test tests/ComWatch.Tests.csproj -c Release

selftest: build ## Run the bundled self-test (expects exit 2)
	-$(DOTNET) run -c Release --no-build -- --selftest

demo: ## Run the full demo script
	bash examples/demo.sh

publish: ## Publish a self-contained single-file binary for the host RID
	$(DOTNET) publish -c Release -p:PublishSingleFile=true --self-contained true -o dist

docker: ## Build the container image
	docker build -t comwatch:latest .

fmt: ## Format the code
	$(DOTNET) format || true

clean: ## Remove build artifacts
	rm -rf bin obj dist tests/bin tests/obj
