FROM golang:1.19@sha256:4eb9ffc8fa980d304aa8d24e00142470538be4cd459717a71495ea11467df124 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:3778d4faa3e5cc2249555b7d4bf1b9da1c529bb3362a4d3f71b6560444a1a430
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
