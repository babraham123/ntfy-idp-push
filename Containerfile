# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Built on the runner's platform and cross-compiled, so a multi-arch build needs no emulation.
# BUILDPLATFORM, TARGETOS and TARGETARCH are set by BuildKit and podman only; make image enables
# BuildKit for docker.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# modernc.org/sqlite is pure Go, so the binary is fully static.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ntfy-idp-push ./cmd/ntfy-idp-push \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ntfy-idp-push /usr/bin/ntfy-idp-push
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/ntfy-idp-push
# Plain HTTP for the reverse proxy that terminates TLS and signs users in; never publish it directly.
ENV NTFY_IDP_PUSH_LISTEN_HTTP=:8080 \
    NTFY_IDP_PUSH_DATABASE=/var/lib/ntfy-idp-push/db.sqlite
VOLUME /var/lib/ntfy-idp-push
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/ntfy-idp-push", "healthcheck"]
ENTRYPOINT ["/usr/bin/ntfy-idp-push"]
CMD ["serve"]
