.PHONY: attachments clean docker

attachments:
	cargo build --release
	cp target/release/rev05 ../attachments/mysterious

clean:
	cargo clean

docker:
	docker compose up --build -d
