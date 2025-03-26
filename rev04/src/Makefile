GCC := gcc
COMPOSE := docker compose
PWD := $(shell pwd)

up: compile
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

compile:
	mkdir -p bin
	$(GCC) -s -static src/*.c -o bin/albo

chall: compile
	zip -r albo.zip bin/albo
	mv albo.zip $(PWD)/../attachments/albo.zip
clean: down
	rm -f bin/albo
