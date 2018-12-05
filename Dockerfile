from golang:1.11-alpine

WORKDIR /go/src/github.com/captncraig/secretOperator

ADD . .

RUN go build