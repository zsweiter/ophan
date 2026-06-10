APP_NAME := ophan
VERSION := $(shell cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4)

TARGET_DIR := target/release
TARGET := $(TARGET_DIR)/$(APP_NAME)

DIST_DIR := dist
PACKAGE_NAME := $(APP_NAME)-$(VERSION)

CONFIG_DIR := config
STUB_DIR := stubs
SCRIPT_DIR := scripts

CARGO := cargo

# OS detection
UNAME_OS := $(shell uname -s 2>/dev/null || echo Unknown)
UNAME_ARCH := $(shell uname -m 2>/dev/null || echo Unknown)

ifeq ($(UNAME_OS),Linux)
	OS := linux
else ifeq ($(UNAME_OS),Darwin)
	OS := macos
else
	OS := windows
endif

ifeq ($(UNAME_ARCH),x86_64)
	ARCH := x86_64
else ifeq ($(UNAME_ARCH),aarch64)
	ARCH := aarch64
else ifeq ($(UNAME_ARCH),arm64)
	ARCH := aarch64
else
	ARCH := x86_64
endif

# Format: ophan-{VERSION}-{OS}-{ARCH}.{tar.gz|zip}
PACKAGE_FILE := $(PACKAGE_NAME)-$(OS)-$(ARCH)
PACKAGE_TAR := $(PACKAGE_FILE).tar.gz
PACKAGE_ZIP := $(PACKAGE_FILE).zip
PACKAGE_DIR := $(DIST_DIR)/$(PACKAGE_FILE)

.PHONY: \
	all build clean run \
	fmt lint check test fix \
	ci \
	package \
	package-linux package-macos package-windows package-all \
	package-docker \
	checksum \
	install uninstall \
	git-tag release compress

all: fmt lint test build

build:
	$(CARGO) build --release

build-debug:
	$(CARGO) build

run:
	$(CARGO) run

compress:
	upx --best $(TARGET) 2>/dev/null || true

clean:
	rm -rf $(DIST_DIR)
	$(CARGO) clean

fmt:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

check:
	$(CARGO) check --all-targets

test:
	$(CARGO) test --all --all-targets

fix:
	$(CARGO) fmt --all
	$(CARGO) clippy --fix --allow-dirty --allow-staged

# ── CI pipeline ──────────────────────────────────────────────
ci: fmt lint test package

# ── Platform package (auto-detect) ───────────────────────────
package: build compress
	@echo "=== Packaging for $(OS)-$(ARCH) ==="
	$(MAKE) _package-common
ifeq ($(OS),linux)
	cp $(STUB_DIR)/systemd.service $(PACKAGE_DIR)/stubs/ophan.service
endif
ifeq ($(OS),macos)
	cp $(STUB_DIR)/io.ophan.ophan.plist $(PACKAGE_DIR)/stubs/
endif
	cd $(DIST_DIR) && tar -czf $(PACKAGE_TAR) $(PACKAGE_FILE)
	@echo "✅ Created: $(DIST_DIR)/$(PACKAGE_TAR)"

# ── Linux package ─────────────────────────────────────────────
package-linux: OS := linux
package-linux: ARCH := x86_64
package-linux: PACKAGE_FILE := $(PACKAGE_NAME)-linux-x86_64
package-linux: PACKAGE_TAR := $(PACKAGE_FILE).tar.gz
package-linux: PACKAGE_DIR := $(DIST_DIR)/$(PACKAGE_FILE)
package-linux:
	$(CARGO) build --release
	upx --best target/release/$(APP_NAME) 2>/dev/null || true
	$(MAKE) _package-common
	cp $(STUB_DIR)/systemd.service $(PACKAGE_DIR)/stubs/ophan.service
	cd $(DIST_DIR) && tar -czf $(PACKAGE_TAR) $(PACKAGE_FILE)
	@echo "✅ Created: $(DIST_DIR)/$(PACKAGE_TAR)"

# ── macOS package ─────────────────────────────────────────────
package-macos: OS := macos
package-macos: ARCH := x86_64
package-macos: PACKAGE_FILE := $(PACKAGE_NAME)-macos-x86_64
package-macos: PACKAGE_TAR := $(PACKAGE_FILE).tar.gz
package-macos: PACKAGE_DIR := $(DIST_DIR)/$(PACKAGE_FILE)
package-macos:
	$(CARGO) build --release
	upx --best target/release/$(APP_NAME) 2>/dev/null || true
	$(MAKE) _package-common
	cp $(STUB_DIR)/io.ophan.ophan.plist $(PACKAGE_DIR)/stubs/
	cd $(DIST_DIR) && tar -czf $(PACKAGE_TAR) $(PACKAGE_FILE)
	@echo "✅ Created: $(DIST_DIR)/$(PACKAGE_TAR)"

# ── Windows package (cross-compile) ──────────────────────────
package-windows: OS := windows
package-windows: ARCH := x86_64
package-windows: PACKAGE_FILE := $(PACKAGE_NAME)-windows-x86_64
package-windows: PACKAGE_ZIP := $(PACKAGE_FILE).zip
package-windows: PACKAGE_DIR := $(DIST_DIR)/$(PACKAGE_FILE)
package-windows:
	$(CARGO) build --release --target x86_64-pc-windows-msvc
	-upx --best target/x86_64-pc-windows-msvc/release/$(APP_NAME).exe 2>/dev/null
	$(MAKE) _package-common TARGET=target/x86_64-pc-windows-msvc/release/$(APP_NAME).exe
	cp $(STUB_DIR)/windows-service.ps1 $(PACKAGE_DIR)/stubs/
	cp $(SCRIPT_DIR)/install.ps1 $(PACKAGE_DIR)/
	cd $(DIST_DIR) && zip -r $(PACKAGE_ZIP) $(PACKAGE_FILE)
	@echo "✅ Created: $(DIST_DIR)/$(PACKAGE_ZIP)"

# ── All platforms (for CI release) ───────────────────────────
package-all: package-linux package-macos package-windows checksum

# ── Docker ────────────────────────────────────────────────────
package-docker:
	@echo "=== Building Docker image ==="
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t $(APP_NAME):$(VERSION) \
		-t $(APP_NAME):latest \
		.
	@echo "✅ Docker image: $(APP_NAME):$(VERSION)"

# ── Checksums ─────────────────────────────────────────────────
checksum:
	@echo "=== Generating checksums ==="
	cd $(DIST_DIR) && \
		for f in *.tar.gz *.zip; do \
			[ -f "$$f" ] && sha256sum "$$f" > "$$f.sha256" && echo "  $$f.sha256"; \
		done
	@echo "✅ Checksums generated"

# ── Internal: common packaging steps ──────────────────────────
_package-common:
	rm -rf $(PACKAGE_DIR)
	mkdir -p $(PACKAGE_DIR)/stubs

	# Binary
	cp $(or $(TARGET),target/release/$(APP_NAME)) $(PACKAGE_DIR)/$(APP_NAME)$(suffix $(or $(TARGET),target/release/$(APP_NAME)))

	# Config
	if [ -d "$(CONFIG_DIR)" ]; then \
		cp -r $(CONFIG_DIR) $(PACKAGE_DIR)/config; \
	fi

	# Install script
	if [ -f "$(SCRIPT_DIR)/install.sh" ] && [ "$(OS)" != "windows" ]; then \
		cp $(SCRIPT_DIR)/install.sh $(PACKAGE_DIR)/install.sh; \
		chmod +x $(PACKAGE_DIR)/install.sh; \
	fi

	# Docs
	cp README.md LICENSE* $(PACKAGE_DIR)/ 2>/dev/null || true

# ── System install ────────────────────────────────────────────
install:
	cargo build --release
	@echo "=== Installing $(APP_NAME) ==="

	# 1. Binary
	sudo install -Dm755 target/release/ophan /usr/local/bin/$(APP_NAME)

	# 2. Sensitive assets (certs, chown, permissions)
	sudo ./scripts/copy-certs.sh

	# 3. Config from .config/ → /etc/ophan/
	sudo mkdir -p /etc/$(APP_NAME)
	sudo cp -r .config/* /etc/$(APP_NAME)/

	# 4. Systemd service (replace @SBINDIR@, @CONFIGDIR@)
	sed "s|@SBINDIR@|/usr/local/bin|g; s|@CONFIGDIR@|/etc/$(APP_NAME)|g" \
		$(STUB_DIR)/systemd.service > /tmp/$(APP_NAME).service
	sudo install -Dm644 /tmp/$(APP_NAME).service /etc/systemd/system/$(APP_NAME).service

	# 5. Register + start
	sudo systemctl daemon-reload
	sudo systemctl enable $(APP_NAME)
	sudo systemctl restart $(APP_NAME)

	@echo "✅ $(APP_NAME) installed: binary + config + service registered"

uninstall:
	@echo "=== Uninstalling $(APP_NAME) ==="
	-sudo systemctl stop $(APP_NAME)
	-sudo systemctl disable $(APP_NAME)
	-sudo rm -f /etc/systemd/system/$(APP_NAME).service
	sudo systemctl daemon-reload
	-sudo rm -f /usr/local/bin/$(APP_NAME)
	-sudo rm -rf /etc/$(APP_NAME)
	@echo "✅ $(APP_NAME) uninstalled"

git-tag:
	git tag v$(VERSION)
	git push origin v$(VERSION)

release: clean all package-all git-tag
