FROM golang:1.23@sha256:adfbe17b774398cb090ad257afd692f2b7e0e7aaa8ef0110a48f0a775e3964f4 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:97d15218016debb9b6700a8c1c26893d3291a469852ace8d8f7d15b2f156920f
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
