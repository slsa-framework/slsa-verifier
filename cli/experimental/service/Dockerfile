FROM golang:1.23@sha256:4b1ecd859fb212b81bdee255dcc8d6d045357d564cdb4dc540a9b0f499f4811e AS base
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
