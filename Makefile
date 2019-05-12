test:
	go test -timeout 20s -coverprofile coverage.out -covermode=atomic ./...
.PHONY: test

build:
	go build
.PHONY: build

install:
	go install
.PHONY: install