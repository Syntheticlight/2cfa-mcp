.PHONY: all build build-linux-arm64 build-linux-amd64 test clean run

BINARY_NAME=2cfa-mcp
BUILD_DIR=build
LDFLAGS=-ldflags="-s -w"

all: test build

build:
	@echo "Building local binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

build-linux-arm64:
	@echo "Cross-compiling for Linux / Android Termux (arm64)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server

build-linux-amd64:
	@echo "Cross-compiling for Linux VPS (amd64)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server

test:
	@echo "Running unit & security tests..."
	go test -v ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

run: build
	./$(BUILD_DIR)/$(BINARY_NAME) -token=dev-token-12345
