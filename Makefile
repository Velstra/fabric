# Velstra — developer convenience targets.
# The real work is plain cargo; these just wrap the common invocations.

IFACE  ?= eth0
CONFIG ?= examples/rules.toml
BIN    := ./target/release/velstra

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build everything in release mode (embeds the eBPF object)
	cargo build --release

.PHONY: test
test: ## Run the full test suite (no root required)
	cargo test --workspace --exclude velstra-ebpf

.PHONY: e2e
e2e: build ## Run the end-to-end suite: loads real eBPF on dummy interfaces (needs root)
	sudo ./tests/e2e/run.sh

.PHONY: test-fast
test-fast: ## Run only the pure-logic tests (no eBPF toolchain needed)
	cargo test -p velstra-common

.PHONY: lint
lint: ## fmt check + clippy on the host crates
	cargo fmt --all -- --check
	cargo clippy -p velstra-common -p velstra --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Auto-format the workspace
	cargo fmt --all

.PHONY: validate
validate: build ## Validate $(CONFIG) without touching the kernel
	$(BIN) validate $(CONFIG)

.PHONY: run
run: build ## Load + attach the firewall on $(IFACE) using $(CONFIG) (needs root)
	sudo -E $(BIN) run --iface $(IFACE) --config $(CONFIG)

.PHONY: check
check: lint test ## What CI runs: lint + test

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
