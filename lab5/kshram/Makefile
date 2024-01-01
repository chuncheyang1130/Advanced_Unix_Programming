
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all: 
	make -C ~/lab5/dist/modulebuild M=$(PWD) modules

kshram: kshram.c
	gcc -o $@ $< -Wall -static

clean:
	make -C ~/lab5/dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp hello hellomod.ko ../rootfs/modules
