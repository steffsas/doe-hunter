# see https://docs.docker.com/language/golang/build-images/

### BUILDER IMAGE
FROM golang:1.22.3-bullseye as builder

WORKDIR /app

# install dependencies
COPY go.mod go.sum go.work go.work.sum /app/
COPY lib/go.mod lib/go.sum /app/lib/
RUN go mod download

# copy source code
COPY . /app

# build go binary
RUN go build -o /app/scanner .

### RUNTIME IMAGE

FROM golang:1.22.3-bullseye as runner

WORKDIR /app

# copy go binary
COPY --from=builder /app/scanner /app/scanner

# copy default.env
COPY --from=builder /app/default.env /app/default.env

ENTRYPOINT [ "/app/scanner" ]
CMD [""]