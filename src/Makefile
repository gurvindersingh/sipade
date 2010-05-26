#Makefile
CC=gcc
LDFLAGS=-lpq -lyaml -lm
CFLAGS=-O3 
DCFLAGS=-g
PCFLAGS=-g -pg
ifneq (${DEBUG},)
CFLAGS = -g -DDEBUG -Wall -Wno-pointer-sign -Wno-nonnull
endif

OBJECTS = util-log.o util-detection.o util-alert.o util-cdr.o util-conf.o sipade.o

all: sipade

sipade: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

debug:
	 ${MAKE} DEBUG=y

profile:
	${MAKE} CFLAGS+='${PCFLAGS}'

clean:
	-rm -v $(OBJECTS)
	-rm sipade

indent:
	find -type f -name '*.[ch]' | xargs indent -kr -i4 -cdb -sc -sob -ss -ncs -ts8 -nut

# oldschool header file dependency checking.
deps:
	-rm -f deps.d
	for i in $(subst .o,.c,$(OBJECTS)); do gcc -MM $$i >> deps.d; done

ifneq ($(wildcard deps.d),)
include deps.d
endif

tags: *.h *.c
	ctags -R
