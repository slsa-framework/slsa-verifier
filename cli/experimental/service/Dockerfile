FROM golang:1.19@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:42311d85daf49d0822fad6961031f0de2015fc94ff6e49a7f30cab9b40553bfb
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
