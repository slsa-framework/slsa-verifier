FROM golang:1.23@sha256:dd5cc4b4f85d13329cb5b17cbf35c509e1c82a43bf6e5961516fda444013121a AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:e00da4d3bd422820880b080115b3bad24349bef37ed46d68ed0d13e150dc8d67
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
