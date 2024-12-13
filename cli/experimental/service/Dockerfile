FROM golang:1.23@sha256:574185e5c6b9d09873f455a7c205ea0514bfd99738c5dc7750196403a44ed4b7 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:6d4a4f40e93615df1677463ca56456379cc3a4e2359308c9e72bc60ffc4a12a9
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
