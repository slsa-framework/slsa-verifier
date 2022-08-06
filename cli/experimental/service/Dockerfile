FROM golang:1.18@sha256:1bbb02af44e5324a6eabe502b6a928d368977225c0255bc9aca4a734145f86e1 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:49d2923f35d66b8402487a7c01bc62a66d8279cd42e89c11b64cdce8d5826c03
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
