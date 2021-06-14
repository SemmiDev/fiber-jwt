.PHONY: app
include .env

run:
	./cmd/env .env go run main.go

build:
	./cmd/env .env go build -o bin/fiber_jwt

runapp:
	./cmd/env .env ./bin/fiber_jwt
