FROM golang:1.21@sha256:f2eb989b0b5579b75652b72ee7b3b04cb1736fc254d7efbf3e492d4c9ea7235a AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:53745e95f227cd66e8058d52f64efbbeb6c6af2c193e3c16981137e5083e6a32
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
