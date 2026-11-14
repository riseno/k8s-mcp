# Release image: the prebuilt static musl binary on distroless, no shell, no build stage.
# The build context holds one binary per platform (see .github/workflows/publish-container.yml):
#   linux/amd64/k8s-mcp
#   linux/arm64/k8s-mcp
FROM gcr.io/distroless/static:nonroot
ARG TARGETPLATFORM
COPY --chmod=0755 ${TARGETPLATFORM}/k8s-mcp /usr/local/bin/k8s-mcp
# Numeric UID so Kubernetes `runAsNonRoot` can verify it.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/k8s-mcp"]
