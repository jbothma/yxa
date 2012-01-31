# $Id$
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
privdir = ${exec_prefix}/lib/yxa/priv
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
	event_handler.erl \
	event_handler_csyslog.erl

imported_hrl_FILES = \
	../include/siprecords.hrl \
	../include/yxa_config.hrl


hrl_FILES = \


yxa_hrl_FILES = $(imported_hrl_FILES) $(hrl_FILES)

CC = gcc
CFLAGS = -Wall

beam_FILES = $(addprefix $(ebin_dir)/, $(erl_FILES:.erl=.beam))

all: $(beam_FILES) syslog_c-port

install: $(beam_FILES) syslog_c-port
	$(mkinstalldirs) $(DESTDIR)$(beamdir)
	$(mkinstalldirs) $(DESTDIR)$(privdir)
	for p in $(beam_FILES); do \
	  $(install_DATA) $$p $(DESTDIR)$(beamdir)/$$f ; \
	done
	for p in syslog_c-port; do \
	  $(install_PROGRAM) $$p $(DESTDIR)$(privdir)/$$f ; \
	done

packages:

distclean: clean
	rm -f Makefile

clean:
	rm -f core *.core *~
	rm -f syslog_c-port *.beam *.script *.start *.boot *.rel *.app *.script
	rm -f *.o ktrace.out erl_crash.dump
	rm -f $(beam_FILES)

doc:
	mkdir -p $(doc_dir)/html/src/event_handler
	cp $(srcdir)/overview.edoc $(doc_dir)/html/src/event_handler/
	$(ERL) $(YXA_EDOC_ARGS) -pa $(ebin_dir) -noshell \
		-yxa_edoc_dir $(doc_dir)/html/src/event_handler \
		-yxa_edoc_srcpath $(srcdir) \
		-run yxa_edoc run "$(erl_FILES)" \
		-run init stop

$(beam_FILES): $(yxa_hrl_FILES)

SUFFIXES = .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in
.SUFFIXES:
.SUFFIXES: .c .o .hrl .beam .erl .boot .rel .rel-in .app .app-in

$(ebin_dir)/%.beam:	$(srcdir)/%.erl
	$(ERLC) $(L_ERLC_FLAGS) $<

syslog_c-port: syslog_c-port.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o syslog_c-port syslog_c-port.o
