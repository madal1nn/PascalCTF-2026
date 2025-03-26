BIN=curly-crab
TARGET_DIR=target/release-stripped
SRC_DIR=src

.PHONY: all build run clean strip

all: build

build:
	cargo build --release

run: build
	$(TARGET_DIR)/$(BIN)

strip: build
	mkdir -p $(TARGET_DIR)
	cp target/release/$(BIN) $(TARGET_DIR)/$(BIN)
	strip $(TARGET_DIR)/$(BIN)

chall: strip
	cp target/release/$(BIN) ../attachments/$(BIN)

clean:
	cargo clean
	rm -rf $(TARGET_DIR)
