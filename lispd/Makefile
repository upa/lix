#Makefile
#char code "LF(UNIX)" is required!!

OPTIONS = -O1
PROGS = main

all: $(PROGS)

main: main.o request.o utils.o route.o encapsulate.o register.o queue.o netlink.o parser.o cli.o reply.o
	cc $(OPTIONS) -o lispd main.o request.o utils.o route.o queue.o encapsulate.o register.o netlink.o parser.o cli.o reply.o -l ssl -l pthread
	rm *.o

main.o : main.c
	cc $(OPTIONS) -c main.c

register.o : register.c
	cc $(OPTIONS) -c register.c

request.o : request.c
	cc $(OPTIONS) -c request.c

utils.o : utils.c
	cc $(OPTIONS) -c utils.c

route.o : route.c
	cc $(OPTIONS) -c route.c

encapsulate.o : encapsulate.c
	cc $(OPTIONS) -c encapsulate.c

queue.o : queue.c
	cc $(OPTIONS) -c queue.c

netlink.o : netlink.c
	cc $(OPTIONS) -c netlink.c

parser.o : parser.c
	cc $(OPTIONS) -c parser.c

cli.o : cli.c
	cc $(OPTIONS) -c cli.c

reply.o : reply.c
	cc $(OPTIONS) -c reply.c
