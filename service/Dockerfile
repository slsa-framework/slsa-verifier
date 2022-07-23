FROM golang:1.18@sha256:9349ed889adb906efa5ebc06485fe1b6a12fb265a01c9266a137bb1352565560 AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN cd service && \
    go build -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor && \
    mv service ../slsa-verifier

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:49d2923f35d66b8402487a7c01bc62a66d8279cd42e89c11b64cdce8d5826c03
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
