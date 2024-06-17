PACKAGE		:= $(shell go list)
PACKAGES	:= $(shell go list ./...)
BINARY_NAME := $(shell basename $(PACKAGE))

COMMIT_SHA	:= $(shell git rev-parse HEAD)
TAG 		:= $(shell git describe --tags --abbrev=0)

# embed version info into binary
LDFLAGS = -ldflags "-X main.Tag=$(TAG) -X main.Build=$(COMMIT_SHA)"

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: help tidy dep build clean
default: help

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "${YELLOW}%-16s${GREEN}%s${RESET}\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Tidy up the go modules
	@go mod tidy

dep: tidy ## Install dependencies
	@go mod download

build: dep ## Build the binary file
	@go build -o build/$(BINARY_NAME) $(LDFLAGS)

clean: ## Remove previous build
	@rm -rf build
