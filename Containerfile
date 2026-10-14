# syntax=docker/dockerfile:1
FROM docker.io/library/golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# modernc.org/sqlite is pure Go, so the binary is fully static.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ntfy-idp-push ./cmd/ntfy-idp-push \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ntfy-idp-push /usr/bin/ntfy-idp-push
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/ntfy-idp-push
# Unprivileged port inside the container; publish it as 443 (IdPs always dial https://<hostname>/).
ENV NTFY_IDP_PUSH_LISTEN_HTTPS=:8443 \
    NTFY_IDP_PUSH_DATABASE=/var/lib/ntfy-idp-push/db.sqlite \
    NTFY_IDP_PUSH_ACME_STORAGE=/var/lib/ntfy-idp-push/acme
VOLUME /var/lib/ntfy-idp-push
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/ntfy-idp-push", "healthcheck", "https://127.0.0.1:8443/healthz"]
ENTRYPOINT ["/usr/bin/ntfy-idp-push"]
CMD ["serve"]
