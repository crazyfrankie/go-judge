FROM golang:1.24.3-alpine

RUN apk add --no-cache coreutils inotify-tools

WORKDIR /app
CMD ["/app/entrypoint.sh"]
