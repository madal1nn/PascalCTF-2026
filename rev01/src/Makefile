COMPOSE := docker compose
PWD := $(shell pwd)

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

chall:
	cp main.gyat ../attachments/AuraTester2000.gyat
	sed -i 's/pascalCTF{[^}]*}/pascalCTF{REDACTED}/g' $(PWD)/../attachments/AuraTester2000.gyat