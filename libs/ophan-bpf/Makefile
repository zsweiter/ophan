# Makefile for ophan-bpf

SHELL := /bin/bash

.PHONY: all help deps build test build-example run-example test-waf clean check

all: help

help:
	@echo "Usage:"
	@echo "  make deps          - Install system dependencies for eBPF and Rust"
	@echo "  make build         - Build the XDP binary (bpfel-unknown-none)"
	@echo "  make test          - Run host-side unit and integration tests"
	@echo "  make build-example - Build the trusted-waf example"
	@echo "  make run-example   - Run the trusted-waf example"
	@echo "  make test-waf      - Test the WAF with curl"
	@echo "  make clean         - Clean build artifacts"

## deps: Install necessary packages for eBPF and Rust (Debian/Ubuntu)
deps:
	@echo "Installing eBPF/Rust dependencies..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-generic bpftool
	@echo "Installing Rustup and nightly toolchain..."
	curl --proto '=https' --tlsv1.2 -sSf https://rustup.rs | sh -s -- -y
	source $$HOME/.cargo/env && rustup toolchain install nightly && rustup default nightly

## build: Compile the XDP binary for BPF target
build:
	@echo "Compiling ophan-bpf (bpfel-unknown-none)..."
    ## cargo +nightly build --release -p ophan-bpf --features xdp
	cargo +nightly build --target=bpfel-unknown-none -Z build-std=core --release -p ophan-bpf --features xdp

    ## build: Compile the XDP binary for BPF target
check:
	cargo +nightly check --target=bpfel-unknown-none -Z build-std=core -p ophan-bpf --features xdp

## test: Run host-side tests (unit + integration, no BPF required)
test:
	@echo "Running tests..."
	sudo $(shell which cargo) test -p ophan-bpf

## build-example: Compile the trusted-waf example
build-example:
	@echo "Building trusted-waf example..."
	cargo build --release --example trusted-waf

## run-example: Run the trusted-waf example
run-example:
	@echo "Running trusted-waf (type 'disable'/'enable' to toggle)..."
	sudo cargo run --example trusted-waf

## test-waf: Test the WAF with curl (run example in another terminal first)
test-waf:
	@echo "Testing WAF (expected: connection timeout = DROP)..."
	curl -m 3 -v http://example.com 2>&1 | tail -5 || echo "(timeout expected - WAF is blocking non-trusted IPs)"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	cargo clean
