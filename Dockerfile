FROM golang:latest as build

WORKDIR /go/src/app

COPY . /go/src/app/

RUN go get -d -v ./...
ENV CGO_ENABLED=0
ENV GOOS=linux
RUN go build -o /go/bin/app

FROM gcr.io/distroless/static-debian10
COPY --from=build /go/bin/app /
CMD ["/app"]