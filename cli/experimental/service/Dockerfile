FROM golang:1.21@sha256:b405b620c7b53ef64695c7da7c8396f411f381c1eb7da6713c585dd7eca1559b AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:a9899ccd9868bbd8913c67f6807410abecf766bc9e3c718eb6248f7b3dfb9819
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
