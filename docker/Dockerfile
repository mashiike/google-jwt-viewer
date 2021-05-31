FROM golang:1.16-alpine3.13 as build-env
WORKDIR /go/src/github.com/mashiike/google-jwt-viewer
RUN apk add --no-cache curl tar
ARG SSMWRAP_VERSION=1.0.0
RUN curl -L https://github.com/handlename/ssmwrap/releases/download/v${SSMWRAP_VERSION}/ssmwrap_v${SSMWRAP_VERSION}_linux_amd64.tar.gz | tar zxvf - && \
    install ssmwrap_v${SSMWRAP_VERSION}_linux_amd64/ssmwrap /usr/local/bin/
COPY . .
RUN go mod tidy && go build -o /usr/local/bin/google-jwt-viewer .

FROM alpine:3.13
RUN apk --no-cache add ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime
WORKDIR /root/
ENV TZ=Asia/Tokyo
ENV AWS_REGION=ap-northeast-1
ENV SSMWRAP_PATHS=/google-jwt-viewer/
COPY --from=build-env /usr/local/bin/google-jwt-viewer /usr/local/bin/
COPY --from=build-env /usr/local/bin/ssmwrap           /usr/local/bin/
EXPOSE 8000
ENTRYPOINT [ "ssmwrap" ]
CMD ["google-jwt-viewer"]
