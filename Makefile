VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/babraham123/ntfy-idp-push
ENGINE  ?= $(shell command -v podman 2>/dev/null || echo docker)

.PHONY: build test image lint
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ntfy-idp-push ./cmd/ntfy-idp-push

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go tool staticcheck ./...
	go tool govulncheck ./...

image:
	DOCKER_BUILDKIT=1 $(ENGINE) build -f Containerfile --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .
