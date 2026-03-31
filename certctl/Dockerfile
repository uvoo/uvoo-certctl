FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X certctl/cmd.version=${VERSION} -X certctl/cmd.commit=${COMMIT} -X certctl/cmd.date=${BUILD_DATE}" \
  -o /out/certctl .

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/certctl /usr/local/bin/certctl

WORKDIR /work

ENTRYPOINT ["certctl"]
