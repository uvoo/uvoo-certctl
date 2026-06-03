FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X uvoo-certctl/cmd.version=${VERSION} -X uvoo-certctl/cmd.commit=${COMMIT} -X uvoo-certctl/cmd.date=${BUILD_DATE}" \
  -o /out/uvoo-certctl .

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends sqlite3 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/uvoo-certctl /usr/local/bin/uvoo-certctl

WORKDIR /work

ENTRYPOINT ["uvoo-certctl"]
