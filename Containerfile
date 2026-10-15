# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Built on the runner's platform and cross-compiled, so a multi-arch build needs no emulation.
# BUILDPLATFORM, TARGETOS and TARGETARCH are set by BuildKit and podman only; make image enables
# BuildKit for docker.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27 AS build
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
# Unprivileged port inside the container; publish it as 443 (IdPs always dial https://<hostname>/).
ENV NTFY_IDP_PUSH_LISTEN_HTTPS=:8443 \
    NTFY_IDP_PUSH_DATABASE=/var/lib/ntfy-idp-push/db.sqlite
VOLUME /var/lib/ntfy-idp-push
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/ntfy-idp-push", "healthcheck", "https://127.0.0.1:8443/healthz"]
ENTRYPOINT ["/usr/bin/ntfy-idp-push"]
CMD ["serve"]
