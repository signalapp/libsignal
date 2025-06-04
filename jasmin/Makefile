AS ?= as
CC ?= gcc
CFLAGS ?= -Wall -Ofast


LIBJADE := ../../../../libjbn/src
SRCS := fq.jazz
OBJ := $(SRCS:%.jazz=%.o)

JFLAGS =
JINCLUDE = -I Libjbn:$(LIBJADE)
JASMIN ?= jasminc
JASMINC := $(JASMIN) $(JFLAGS) $(JINCLUDE)
COMPILE = ($(JASMINC) -o $@ $<)

# --------------------------------------------------------------------
.PHONY: default compile clean
.INTERMEDIATE: $(OBJ)

default: fq

fq: $(OBJ)
	ar -rc libfq.a $(OBJ)
	ranlib libfq.a

compile: $(SRCS:%.jazz=%.s)

%.s: %.jazz
	$(COMPILE)

clean:
	@rm -fr *.s *.o *.a
