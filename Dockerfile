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

ENV DOE_RUN_TYPE=""
ENV DOE_PROTOCOL_TYPE=""
ENV DOE_KAFKA_SERVER="localhost:9092"
ENV DOE_PARALLEL_CONSUMER="1"

COPY --from=builder /app/scanner /app/scanner

CMD ["/app/scanner"]