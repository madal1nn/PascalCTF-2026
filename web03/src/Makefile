COMPOSE := docker compose
PWD := $(shell pwd)

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

chall:
	cp -r app/ app1/
	echo "pascalCTF{REDACTED}" > app1/flag.txt
	cd app1 && zip -r ../travel.zip . && cd ..
	mv travel.zip $(PWD)/../attachments/travel.zip
	rm -rf app1
clean: down
	rm -f travel.zip