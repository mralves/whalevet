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
# The build context holds a static copy of the running whalevet binary plus
# this Dockerfile, staged by the CLI helper; the wrapper is assembled from
# that binary instead of a source checkout, so it builds from a released
# binary too.
#
# The values are base64 JSON; the CLI helper does the encoding:
#   RULES_JSON = base64(json([{type, ...}]))
#   CERTS_JSON  = base64(json({"basename.crt": base64(pem)}))

FROM scratch
COPY whalevet /whalevet
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.inputs,moby.buildkit.frontend.subrequests,moby.buildkit.frontend.contexts"
ARG RULES_JSON=""
ARG CERTS_JSON=""
ENV PROXY_RULES_JSON=$RULES_JSON
ENV PROXY_CERTS_JSON=$CERTS_JSON
ENTRYPOINT ["/whalevet", "frontend"]