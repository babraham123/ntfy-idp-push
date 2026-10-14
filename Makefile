VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/babraham123/ntfy-idp-push
ENGINE  ?= $(shell command -v podman 2>/dev/null || echo docker)

.PHONY: build test image lint
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ntfy-idp-push ./cmd/ntfy-idp-push

test:
	go test -race ./...

lint:
	go vet ./...

image:
	$(ENGINE) build -f Containerfile --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .
