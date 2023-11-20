# © 2023 Snyk Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
SHELL := /bin/bash

ifeq ($(CIRCLE_SHA1),)
	GIT_COMMIT := $(shell git rev-parse --verify --short HEAD)
else 
	GIT_COMMIT := $(CIRCLE_SHA1)
endif

ifeq ($(CIRCLE_TAG),)
	TAG := v0.0.0-$(GIT_COMMIT)
else
	TAG := $(CIRCLE_TAG)
endif


GOCMD=go
GOMOD=$(GOCMD) mod
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOTOOL=$(GOCMD) tool

COVERAGEDIR=coverage
COVERAGEFILE=$(COVERAGEDIR)/coverage.out
COVERAGEHTML=$(subst .out,.html,$(COVERAGEFILE))

all: fmt lint tidy test build
	$(info  "completed running make file for golang project")
fmt:
	@go fmt ./...
lint:
	env GOROOT=$$(go env GOROOT) golangci-lint run ./...
tidy:
	$(GOMOD) tidy -v
test:
	$(GOTEST) ./...
.PHONY: coverage
coverage:
	./scripts/coverage.sh
.PHONY: license
license:
	./scripts/license.py $(PARAM)
build:
	$(GOBUILD) -v ./...
release:
	npx \
		-p '@semantic-release/commit-analyzer' \
		-p 'conventional-changelog-conventionalcommits' \
		-p '@semantic-release/github' \
		semantic-release

