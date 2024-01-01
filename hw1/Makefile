CC		= gcc
CFLAGS	= -fPIC -ldl
PROGS	= sandbox.so

all: $(PROGS)
	mkdir logs
	mkdir filter

sandbox.so: sandbox.c 
	$(CC) -o $@ -shared $^ $(CFLAGS)

clean:
	rm -r ./logs
	rm -r ./filter
	rm -r index.html*