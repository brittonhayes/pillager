FROM golang:1.17-alpine

WORKDIR /src/
COPY . /src/
RUN CGO_ENABLED=0 go build -v -o /bin/pillager cmd/pillager/main.go

LABEL author="Britton Hayes"
LABEL github="https://github.com/brittonhayes/pillager"

ENTRYPOINT ["/bin/pillager"]

CMD [ "/bin/pillager" ]