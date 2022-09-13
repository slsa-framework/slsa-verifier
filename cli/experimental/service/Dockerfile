FROM golang:1.18@sha256:87109c63a727f5125a5cf9f2341aaed5da1f2e0d2cb7b2c99ee5355c6cf05cbf AS base
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
