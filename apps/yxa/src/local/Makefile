# $Id: Makefile.in 3031 2006-02-14 13:17:09Z ft $
#

srcdir = .
top_srcdir = ../..

prefix = /usr/local
DESTDIR = 
SHELL = /bin/bash

confdir = ${prefix}/etc
sslcertdir = ${confdir}
mnesiadir = /var/yxa/db
beamdir = ${exec_prefix}/lib/yxa/ebin
includedir = ${exec_prefix}/lib/yxa/include
sbindir = ${exec_prefix}/sbin
exec_prefix=${prefix}
builddir = .

ebin_dir = ../../ebin
doc_dir = ../../doc
yxa_include_dir = $(srcdir)/../include/

ERLC = /usr/local/bin/erlc
ERL = /usr/local/bin/erl
L_ERLC_FLAGS = $(ERLC_FLAGS) -o $(ebin_dir) -I$(srcdir) -I$(yxa_include_dir)

INSTALL = /usr/bin/install -c
install_DATA = ${INSTALL} -m 644
install_PROGRAM = ${INSTALL}

mkinstalldirs = $(SHELL) $(top_srcdir)/scripts/mkinstalldirs


erl_FILES =

imported_hrl_FILES =

hrl_FILES =

yxa_hrl_FILES = $(imported_hrl_FILES) $(hrl_FILES)

CC = gcc
CFLAGS = -Wall

beam_FILES = $(addprefix $(ebin_dir)/, $(erl_FILES:.erl=.beam))

all: $(beam_FILES)

install: $(beam_FILES) $(hrl_FILES)

packages:

distclean: clean
	rm -f Makefile

clean:
	rm -f core *.core *~
	rm -f *.beam *.script *.start *.boot *.rel *.app *.script
	rm -f *.o ktrace.out erl_crash.dump

doc:
	mkdir -p $(doc_dir)/html/src/local
	cp $(srcdir)/overview.edoc $(doc_dir)/html/src/local/
	$(ERL) $(YXA_EDOC_ARGS) -pa $(ebin_dir) -noshell \
		-yxa_edoc_dir $(doc_dir)/html/src/local \
		-yxa_edoc_srcpath $(srcdir) \
		-run yxa_edoc run "" \
		-run init stop

$(beam_FILES): $(yxa_hrl_FILES)

SUFFIXES = .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in
.SUFFIXES:
.SUFFIXES: .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in

.erl.beam:
	$(ERLC) $(L_ERLC_FLAGS) $<
