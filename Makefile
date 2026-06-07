.PHONY: build test license-check release

build:
	go build ./...

test:
	go test ./...

license-check:
	bash scripts/license-check.sh

release:
	bash scripts/build-release.sh
