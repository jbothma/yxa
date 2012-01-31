# $Id: Makefile.in 2565 2005-06-20 14:55:24Z ft $
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
local_file = @local_file@

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

erl_FILES = \
	clienttransaction.erl \
	servertransaction.erl \
	transactionlayer.erl \
	transactionstatelist.erl

imported_hrl_FILES = \
	../include/yxa_config.hrl \
	../include/siprecords.hrl \
	../include/sipsocket.hrl

hrl_FILES = \
	transactionstatelist.hrl


yxa_hrl_FILES = $(imported_hrl_FILES) $(hrl_FILES)

CC = gcc
CFLAGS = -Wall

beam_FILES = $(addprefix $(ebin_dir)/, $(erl_FILES:.erl=.beam))

all: $(beam_FILES)

install: $(beam_FILES) $(hrl_FILES)
	$(mkinstalldirs) $(DESTDIR)$(beamdir)
	$(mkinstalldirs) $(DESTDIR)$(includedir)
	for p in $(beam_FILES); do \
	  $(install_DATA) $$p $(DESTDIR)$(beamdir)/$$f ; \
	done
	for p in $(hrl_FILES); do \
	  $(install_DATA) $(srcdir)/$$p $(DESTDIR)$(includedir)/$$f ; \
	done

packages:

distclean: clean
	rm -f Makefile

clean:
	rm -f core *.core *~
	rm -f *.beam *.script *.start *.boot *.rel *.app *.script
	rm -f *.o ktrace.out erl_crash.dump
	rm -f $(beam_FILES)

doc:
	mkdir -p $(doc_dir)/html/src/transactionlayer
	cp $(srcdir)/overview.edoc $(doc_dir)/html/src/transactionlayer/
	$(ERL) $(YXA_EDOC_ARGS) -pa $(ebin_dir) -noshell \
		-yxa_edoc_dir $(doc_dir)/html/src/transactionlayer \
		-yxa_edoc_srcpath $(srcdir) \
		-run yxa_edoc run "$(erl_FILES)" \
		-run init stop

$(beam_FILES): $(yxa_hrl_FILES)

SUFFIXES = .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in
.SUFFIXES:
.SUFFIXES: .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in

$(ebin_dir)/%.beam:	$(srcdir)/%.erl
	$(ERLC) $(L_ERLC_FLAGS) $<

