FROM golang:1.17 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct && go env -w GOPRIVATE=git.real-ai.cn
RUN go mod download

COPY server/server.go /workspace/
RUN CGO_ENABLED=0  GOOS=linux GOARCH=amd64 go build  -a -o server server.go

FROM gcr.airbob.workers.dev/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/server .
USER 65532:65532
ENTRYPOINT ["/server"]