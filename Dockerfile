# Dockerfile

FROM golang:1.24.4

WORKDIR /app

COPY go.mod ./

COPY . .

RUN go mod tidy && go mod download && go mod verify

RUN go build -o main ./cmd/main.go

EXPOSE 8080

CMD ["/app/main"]
