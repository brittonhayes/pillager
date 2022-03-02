FROM golang:1.17-alpine AS build

WORKDIR /src/
COPY . /src/
RUN CGO_ENABLED=0 go build cmd/pillager/main.go -o /bin/pillager

FROM scratch as prod

LABEL author="Britton Hayes"
LABEL github="https://github.com/brittonhayes/pillager"

COPY --from=build /bin/pillager /bin/pillager
ENTRYPOINT ["/bin/pillager"]
