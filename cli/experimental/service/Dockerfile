FROM golang:1.19@sha256:83f9f840072d05ad4d90ce4ac7cb2427632d6b89d5ffc558f18f9577ec8188c0 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:c62385962234a3dae5c9e9777dedc863d99f676b7202cd073e90b06e46021994
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
