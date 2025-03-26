.PHONY: up down attachments

up:
	docker-compose up -d --build

down:
	docker-compose down

attachments:
	mkdir -p pdfile
	cp -r templates pdfile/
	cp app.py requirements.txt Dockerfile docker-compose.yml pdfile/
	sed -i 's/pascalCTF{.*}/pascalCTF{redacted}/g' pdfile/docker-compose.yml
	zip -r pdfile.zip pdfile
	rm -rf pdfile
	mv pdfile.zip ../attachments/