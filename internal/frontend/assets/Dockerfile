# whalevet frontend wrapper image.
# Runs the standard dockerfile frontend with Dockerfile injection rules
# applied. Rules are baked in at image build time (per-build FrontendOpts
# do not survive to directive-triggered frontends).
#
# Selected per-build with a syntax directive:
#   # syntax=whalevet:latest
#
# Build with rules baked in (example):
#   whalevet setup [tag]
#
# The values are base64 JSON; the CLI helper above does the encoding:
#   RULES_JSON = base64(json([{type, ...}]))
#   CERTS_JSON  = base64(json({"basename.crt": base64(pem)}))

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /whalevet ./cmd/...

FROM scratch
COPY --from=build /whalevet /whalevet
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.subrequests,moby.buildkit.frontend.contexts"
ARG RULES_JSON=""
ARG CERTS_JSON=""
ENV PROXY_RULES_JSON=$RULES_JSON
ENV PROXY_CERTS_JSON=$CERTS_JSON
ENTRYPOINT ["/whalevet", "frontend"]
