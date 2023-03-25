# cf. based https://gist.github.com/thomaspoignant/5b72d579bd5f311904d973652180c705
GOCMD=go
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
BINARY_NAME=ipfix-srv6
VERSION?=0.0.0
DOCKER_REGISTRY?= #if set it should finished by /
CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DIFF_FROM_BRANCH_NAME ?= origin/master

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all test stylecheck build

all: help

## Build:
build: ## Build your project and put the output binary in out/bin/
	mkdir -p out/bin
	$(GOCMD) build -o out/bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)/main.go

clean: ## Remove build related file
	rm -fr ./out/bin

## Test:
test: ## Run the tests of the project
	$(GOTEST) -v -exec sudo -race ./... $(OUTPUT_OPTIONS)

## Golang:
go-gen: export BPF_CLANG := $(CLANG)
go-gen: export BPF_CFLAGS := $(CFLAGS)
go-gen: ## go:generate invocations
# BPF_CLANG is used in go:generate invocations.
	go generate ./...

## Help:
help: ## Show this help.
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)