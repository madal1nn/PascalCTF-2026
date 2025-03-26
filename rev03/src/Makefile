SOURCE=main.c

default: attachments clean
	echo "Build complete."

compile: $(SOURCE)
	gcc -static -o vm $(SOURCE)
	python3 generator.py

attachments: compile
	cp vm code.pascal ../attachments/

clean:
	rm -f vm code.pascal