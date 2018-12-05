from golang:1.11-alpine

WORKDIR /go/src/github.com/captncraig/secretOperator

ADD . .

RUN go install

FROM alpine:3.7
WORKDIR /root/
COPY --from=0 /go/bin/secretOperator .
CMD ["/root/secretOperator", "-alsologtostderr"]