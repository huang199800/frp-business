# Manifest digests verified against Docker Hub on 2026-10-23; Docker execution remains unverified locally.
FROM node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 AS web
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /app/cmd/portal/ui/ cmd/portal/ui/
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /portal ./cmd/portal

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS frp
WORKDIR /frp
COPY scripts/fetch-frp.py /src/scripts/fetch-frp.py
COPY third_party/frp-lock.json /src/third_party/frp-lock.json
ARG TARGETARCH
RUN python /src/scripts/fetch-frp.py --os linux --arch $TARGETARCH --out /frp && cp /frp/frp_0.71.1_linux_$TARGETARCH/frps /frps && cp /frp/frp_0.71.1_linux_$TARGETARCH/frpc /frpc

FROM debian:bookworm-20260223-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd -u 10001 -m -s /usr/sbin/nologin portal
COPY --from=build /portal /usr/local/bin/portal
COPY --from=frp /frps /frpc /usr/local/bin/
COPY third_party/ /usr/share/frp-portal/third_party/
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/portal"]
CMD ["serve","--config","/config/control.json"]
