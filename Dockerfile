FROM golang:1.12-alpine as stage-build
LABEL stage=stage-build
WORKDIR /go/src/koko
RUN apk update && apk add git
ARG https_proxy
ARG http_proxy
ENV https_proxy=$https_proxy
ENV http_proxy=$http_proxy
RUN go get -u github.com/golang/dep/cmd/dep
COPY . .
RUN dep ensure -vendor-only && cd cmd && go build koko.go

FROM alpine
WORKDIR /opt/coco/
COPY --from=stage-build /go/src/koko/cmd/koko .
COPY --from=stage-build /go/src/koko/cmd/locale .
COPY --from=stage-build /go/src/koko/cmd/static .
COPY --from=stage-build /go/src/koko/cmd/templates .
RUN  echo > config.yml
EXPOSE 2222
CMD ["./koko"]