# see https://docs.docker.com/language/golang/build-images/

### BUILDER IMAGE
FROM golang:1.22.3-bullseye as builder

WORKDIR /app

COPY . ./

RUN go mod download
RUN go build -o /app/scanner .

### RUNTIME IMAGE

FROM golang:1.22.3-bullseye as runner

WORKDIR /app

# copy go binary
COPY --from=builder /app/scanner /app/scanner

# copy default .env file
COPY --from=builder /app/.env /app/.env

ENTRYPOINT [ "/app/scanner" ]
CMD [""]