FROM golang:alpine AS build
ADD . /go/src/Zendesk-Exporter
WORKDIR /go/src/Zendesk-Exporter
RUN go mod download
RUN CGO_ENABLED=0 go build -o zendesk-exporter ./src

FROM alpine
RUN apk --no-cache add ca-certificates && update-ca-certificates
WORKDIR /app
COPY --from=build /go/src/Zendesk-Exporter/zendesk-exporter /app/
ADD zendesk.yml /app/config/
ENTRYPOINT [ "/app/zendesk-exporter","--config.file=/app/config/zendesk.yml" ]