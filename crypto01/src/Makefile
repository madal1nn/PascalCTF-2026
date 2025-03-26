PWD := $(shell pwd)

chall:
	cp xord.py $(PWD)/../attachments/xord.py
	sed -i 's/pascalCTF{[^}]*}/pascalCTF{REDACTED}/g' $(PWD)/../attachments/xord.py
	FLAG='pascalCTF{1ts_4lw4ys_4b0ut_x0r1ng_4nd_s33d1ng}' python3 xord.py
	mv output.txt $(PWD)/../attachments/output.txt