ARG GOLANG_VERSION="1.19.1"

FROM golang:$GOLANG_VERSION-alpine as builder
RUN apk --no-cache add tzdata
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' -o ./socks5-multiuser

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /go/src/app/socks5-multiuser /
ENTRYPOINT ["/socks5-multiuser"]
