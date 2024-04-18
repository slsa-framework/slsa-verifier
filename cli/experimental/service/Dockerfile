FROM golang:1.21@sha256:81811f8a883e238666dbadee6928ae2902243a3cd3f3e860f21c102543c6b5a7 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:1a8ece87bd75cde87d0484ef48eb60ea25811baf90967265956ae4fa2098dd9d
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
