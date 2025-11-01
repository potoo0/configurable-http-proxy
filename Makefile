LDFLAGS =

# project info
PACKAGE		:= $(shell go list)
PACKAGES	:= $(shell go list ./...)
BINARY_NAME := $(shell basename $(PACKAGE))

# commit info
TAG 		:= $(shell git describe --tags --abbrev=0)

# embed version info into binary
LDFLAGS += -X main.Tag=$(TAG)

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: help tidy dep vet test build clean
default: help
all: test build

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "${YELLOW}%-16s${GREEN}%s${RESET}\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Tidy up the go modules
	@go mod tidy

dep: tidy ## Install dependencies
	@go mod download

fmt: ## Format code with golangci-lint
	@golangci-lint fmt

vet: dep ## Run go vet
	@go vet ./...

quicktest: dep ## Run quicktest, without race detector
	@go test -v ./... -short 2>&1 | tee test.log
	@echo "Written logs in quicktest.log"

test: dep ## Run test
	@go test -cpu=2 -race -v ./... -short 2>&1 | tee test.log
	@echo "Written logs in test.log"

build: dep ## Build the binary file
	@go build -o $(BINARY_NAME) -ldflags '-s -w $(LDFLAGS)'

clean: ## Remove previous build
	@go clean ./...
	@rm -f quicktest.log test.log $(BINARY_NAME)
