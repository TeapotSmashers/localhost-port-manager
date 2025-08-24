ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY go.mod ./
COPY . .
RUN go mod tidy && go mod download && go mod verify
RUN go build -v -o /run-app .


FROM debian:bookworm

# Create config directory and copy config file
RUN mkdir -p /etc/port-redirect
COPY config.txt /etc/port-redirect/config.txt

COPY --from=builder /run-app /usr/local/bin/
CMD ["run-app"]
