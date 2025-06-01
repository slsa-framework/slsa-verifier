FROM golang:1.23@sha256:cc458d7c7df5a4a296daf82cc58a994e668d4489e3519a9cbcc332f1eb60be82 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:5c9b112e85b26632c6ba9ac874be9c6b20d61599f6087534ce2b9feeb7f6babf
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
