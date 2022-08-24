FROM golang:1.18@sha256:616aa980e2a8f3944baf5975d475f6ef1a3e50f1ec56fecd2e88280f5d1b4bf2 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:533c15ef2acb1d3b1cd4e58d8aa2740900cae8f579243a53c53a6e28bcac0684
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
