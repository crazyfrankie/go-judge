FROM golang:1.24.3-alpine

RUN apk add --no-cache coreutils

WORKDIR /app

COPY work/ /app
RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]
