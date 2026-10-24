# SPDX-License-Identifier: GPL-3.0-or-later
#
# trestle - CNI / Netavark plugin attaching rootless containers to host bridges
#
#   make                  build trestle (client) and trestled (server)
#   make check            build and run the unit tests
#   make integration-test run the root-only end-to-end test (network namespaces)
#   make install          install into $(DESTDIR)$(PREFIX)
#   make selinux          build the SELinux policy module (needs selinux-policy-devel)
#   make dist             create trestle-$(VERSION).tar.gz
#   make rpm | deb        build distribution packages
#
# Arch Linux: see packaging/arch/PKGBUILD.

NAME     := trestle
VERSION  := 0.2

PREFIX        ?= /usr
SBINDIR       ?= $(PREFIX)/sbin
BINDIR        ?= $(PREFIX)/bin
LIBEXECDIR    ?= $(PREFIX)/libexec
SYSCONFDIR    ?= /etc
LOCALSTATEDIR ?= /var/lib
DATADIR       ?= $(PREFIX)/share
MANDIR        ?= $(DATADIR)/man
DOCDIR        ?= $(DATADIR)/doc/$(NAME)
UNITDIR       ?= $(PREFIX)/lib/systemd/system
TMPFILESDIR   ?= $(PREFIX)/lib/tmpfiles.d
SELINUXDIR    ?= $(DATADIR)/selinux/packages
# Plugin directories searched by the container runtimes
NETAVARK_PLUGINDIR ?= $(LIBEXECDIR)/netavark
CNI_BINDIR         ?= $(LIBEXECDIR)/cni
# Defaults compiled into trestled (overridable in trestle.conf)
AARDVARK_BINARY    ?= $(LIBEXECDIR)/podman/aardvark-dns
NFT_BINARY         ?= /usr/sbin/nft

CLIENT_PATH := $(LIBEXECDIR)/$(NAME)/$(NAME)

CC      ?= gcc
PKG_CONFIG ?= pkg-config
INSTALL ?= install

JSONC_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c)
JSONC_LIBS   := $(shell $(PKG_CONFIG) --libs json-c)

WARN    := -Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith -Wstrict-prototypes \
           -Wmissing-prototypes -Wno-unused-parameter -Wno-format-truncation
HARDEN  := -fstack-protector-strong -fPIE
# add _FORTIFY_SOURCE unless the distribution flags already set a level
ifeq ($(findstring _FORTIFY_SOURCE,$(CFLAGS) $(CPPFLAGS)),)
HARDEN  += -D_FORTIFY_SOURCE=2
endif
# CFLAGS/LDFLAGS may be overridden (e.g. by rpmbuild); our required flags
# are kept separately so they are never lost.
CFLAGS  ?= -O2 -g
LDFLAGS ?=
ALL_CFLAGS  = -std=gnu11 $(WARN) $(HARDEN) $(JSONC_CFLAGS) $(CFLAGS)
ALL_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now -Wl,--as-needed $(LDFLAGS)

DEFS := -DTRESTLE_VERSION=\"$(VERSION)\" \
        -DTRESTLE_SYSCONFDIR=\"$(SYSCONFDIR)\" \
        -DTRESTLE_LIBEXECDIR=\"$(LIBEXECDIR)\" \
        -DTRESTLE_SBINDIR=\"$(SBINDIR)\" \
        -DTRESTLE_LOCALSTATEDIR=\"$(LOCALSTATEDIR)\" \
        -DTRESTLE_AARDVARK_BINARY=\"$(AARDVARK_BINARY)\" \
        -DTRESTLE_NFT_BINARY=\"$(NFT_BINARY)\"

BUILD := build

COMMON_SRC := src/common/md5.c src/common/log.c src/common/util.c src/common/config.c \
              src/common/naming.c src/common/proto.c src/common/request.c
SERVER_SRC := src/server/main.c src/server/handler.c src/server/netlink.c src/server/checks.c \
              src/server/state.c src/server/dnsout.c src/server/nft.c src/server/bridge.c src/server/hooks.c src/server/netset.c src/server/nm.c src/server/exec.c src/server/firewalld.c src/server/dhcp.c src/server/keeper.c src/server/gc.c
CLIENT_SRC := src/client/trestle.c
SERVER_LIB_SRC := $(filter-out src/server/main.c,$(SERVER_SRC))

COMMON_OBJ := $(COMMON_SRC:%.c=$(BUILD)/%.o)
SERVER_OBJ := $(SERVER_SRC:%.c=$(BUILD)/%.o)
CLIENT_OBJ := $(CLIENT_SRC:%.c=$(BUILD)/%.o)
SERVER_LIB_OBJ := $(SERVER_LIB_SRC:%.c=$(BUILD)/%.o)

UNIT_TESTS := $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(filter-out tests/unit/harness.c,$(wildcard tests/unit/test_*.c)))

.PHONY: fuzz security-test all clean check test integration-test install install-selinux uninstall selinux dist rpm deb

all: $(BUILD)/trestle $(BUILD)/trestled

$(BUILD)/%.o: %.c $(wildcard src/common/*.h src/server/*.h)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(DEFS) $(ALL_CFLAGS) -c -o $@ $<

$(BUILD)/trestle: $(CLIENT_OBJ) $(COMMON_OBJ)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $^ $(JSONC_LIBS)

$(BUILD)/trestled: $(SERVER_OBJ) $(COMMON_OBJ)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $^ $(JSONC_LIBS)

# ---- tests ---------------------------------------------------------------
$(BUILD)/tests/%: tests/unit/%.c tests/unit/harness.h $(COMMON_OBJ) $(SERVER_LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(DEFS) $(ALL_CFLAGS) -Isrc $(ALL_LDFLAGS) -o $@ $< $(COMMON_OBJ) $(SERVER_LIB_OBJ) $(JSONC_LIBS)

check test: $(UNIT_TESTS)
	@fail=0; for t in $(UNIT_TESTS); do echo "== $$t"; $$t || fail=1; done; \
	if [ $$fail -ne 0 ]; then echo "UNIT TESTS FAILED"; exit 1; fi; echo "ALL UNIT TESTS PASSED"

integration-test: all
	tests/integration/run.sh $(CURDIR)/$(BUILD)
	tests/integration/features.sh $(CURDIR)/$(BUILD)

# ---- install -------------------------------------------------------------
install: all
	$(INSTALL) -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBEXECDIR)/$(NAME) \
		$(DESTDIR)$(NETAVARK_PLUGINDIR) $(DESTDIR)$(CNI_BINDIR) \
		$(DESTDIR)$(SYSCONFDIR)/$(NAME)/conf.d $(DESTDIR)$(UNITDIR) $(DESTDIR)$(TMPFILESDIR) \
		$(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(DOCDIR)/examples
	$(INSTALL) -m 0755 $(BUILD)/trestled $(DESTDIR)$(SBINDIR)/trestled
	$(INSTALL) -m 0755 $(BUILD)/trestle $(DESTDIR)$(CLIENT_PATH)
	ln -sf $(CLIENT_PATH) $(DESTDIR)$(NETAVARK_PLUGINDIR)/$(NAME)
	ln -sf $(CLIENT_PATH) $(DESTDIR)$(CNI_BINDIR)/$(NAME)
	ln -sf $(CLIENT_PATH) $(DESTDIR)$(BINDIR)/trestlectl
	@if [ ! -e $(DESTDIR)$(SYSCONFDIR)/$(NAME)/trestle.conf ]; then \
		sed -e 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' -e 's|@SBINDIR@|$(SBINDIR)|g' \
		    -e 's|@LOCALSTATEDIR@|$(LOCALSTATEDIR)|g' -e 's|@AARDVARK_BINARY@|$(AARDVARK_BINARY)|g' \
		    -e 's|@NFT_BINARY@|$(NFT_BINARY)|g' etc/trestle.conf.in \
		    > $(DESTDIR)$(SYSCONFDIR)/$(NAME)/trestle.conf; \
		chmod 0644 $(DESTDIR)$(SYSCONFDIR)/$(NAME)/trestle.conf; \
	else echo "keeping existing $(SYSCONFDIR)/$(NAME)/trestle.conf"; fi
	$(INSTALL) -m 0644 etc/conf.d/README $(DESTDIR)$(SYSCONFDIR)/$(NAME)/conf.d/README
	$(INSTALL) -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/$(NAME)/hooks
	sed -e 's|@SBINDIR@|$(SBINDIR)|g' systemd/trestled.service.in > $(DESTDIR)$(UNITDIR)/trestled.service
	chmod 0644 $(DESTDIR)$(UNITDIR)/trestled.service
	$(INSTALL) -m 0644 systemd/trestle.tmpfiles $(DESTDIR)$(TMPFILESDIR)/trestle.conf
	$(INSTALL) -m 0644 man/trestle.conf.5 $(DESTDIR)$(MANDIR)/man5/
	$(INSTALL) -m 0644 man/trestle.8 man/trestled.8 man/trestlectl.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 0644 README.md docs/*.md $(DESTDIR)$(DOCDIR)/
	$(INSTALL) -m 0644 docs/examples/* $(DESTDIR)$(DOCDIR)/examples/
	$(INSTALL) -d -m 0711 $(DESTDIR)$(LOCALSTATEDIR)/$(NAME)

selinux:
	$(MAKE) -C selinux -f /usr/share/selinux/devel/Makefile trestle.pp

install-selinux: selinux
	$(INSTALL) -d $(DESTDIR)$(SELINUXDIR)
	$(INSTALL) -m 0644 selinux/trestle.pp $(DESTDIR)$(SELINUXDIR)/trestle.pp
	$(INSTALL) -d $(DESTDIR)$(DATADIR)/selinux/devel/include/contrib
	$(INSTALL) -m 0644 selinux/trestle.if $(DESTDIR)$(DATADIR)/selinux/devel/include/contrib/trestle.if

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/trestled $(DESTDIR)$(CLIENT_PATH) \
	      $(DESTDIR)$(NETAVARK_PLUGINDIR)/$(NAME) $(DESTDIR)$(CNI_BINDIR)/$(NAME) \
	      $(DESTDIR)$(UNITDIR)/trestled.service $(DESTDIR)$(TMPFILESDIR)/trestle.conf \
	      $(DESTDIR)$(MANDIR)/man5/trestle.conf.5 $(DESTDIR)$(MANDIR)/man8/trestle.8 \
	      $(DESTDIR)$(MANDIR)/man8/trestled.8 $(DESTDIR)$(MANDIR)/man8/trestlectl.8 \
	      $(DESTDIR)$(BINDIR)/trestlectl
	rm -rf $(DESTDIR)$(DOCDIR)
	-rmdir $(DESTDIR)$(LIBEXECDIR)/$(NAME)

# ---- packaging -----------------------------------------------------------
DIST_FILES := Makefile README.md LICENSE CHANGELOG.md src tests etc systemd selinux man docs packaging debian

dist:
	rm -rf $(BUILD)/dist && mkdir -p $(BUILD)/dist/$(NAME)-$(VERSION)
	cp -a $(DIST_FILES) $(BUILD)/dist/$(NAME)-$(VERSION)/
	find $(BUILD)/dist -name '*.o' -delete
	rm -f $(BUILD)/dist/$(NAME)-$(VERSION)/selinux/*.pp
	rm -rf $(BUILD)/dist/$(NAME)-$(VERSION)/selinux/tmp
	cd $(BUILD)/dist/$(NAME)-$(VERSION)/debian && rm -rf trestle .debhelper files *.substvars *.debhelper *.debhelper.log debhelper-build-stamp
	tar -C $(BUILD)/dist -czf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	@echo "created $(NAME)-$(VERSION).tar.gz"

rpm: dist
	mkdir -p $(BUILD)/rpmbuild/SOURCES
	cp $(NAME)-$(VERSION).tar.gz $(BUILD)/rpmbuild/SOURCES/
	rpmbuild --define "_topdir $(CURDIR)/$(BUILD)/rpmbuild" -ba packaging/rpm/trestle.spec

deb:
	dpkg-buildpackage -us -uc -b

security-test: all
	tests/security/run.sh $(BUILD)

# ---- fuzzing (clang + libFuzzer) ------------------------------------------
FUZZ_CC     ?= clang
FUZZ_FLAGS  := -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
               -DTRESTLE_FUZZ -std=gnu11 -Isrc $(JSONC_CFLAGS) $(DEFS)
FUZZ_TARGETS := request wire proto config dhcp
FUZZ_BINS   := $(FUZZ_TARGETS:%=$(BUILD)/fuzz/fuzz_%)
FUZZ_TIME   ?= 60

$(BUILD)/fuzz/fuzz_%: tests/fuzz/fuzz_%.c $(COMMON_SRC) $(SERVER_LIB_SRC)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -o $@ $< $(COMMON_SRC) $(SERVER_LIB_SRC) $(JSONC_LIBS)

fuzz: $(FUZZ_BINS)
	@for t in $(FUZZ_TARGETS); do \
	  mkdir -p $(BUILD)/fuzz/corpus-$$t; \
	  cp tests/fuzz/seeds/$$t/* $(BUILD)/fuzz/corpus-$$t/ 2>/dev/null || true; \
	  echo "== fuzz_$$t ($(FUZZ_TIME)s)"; \
	  $(BUILD)/fuzz/fuzz_$$t -max_total_time=$(FUZZ_TIME) -max_len=16384 -timeout=10 \
	    -artifact_prefix=$(BUILD)/fuzz/crash-$$t- $(BUILD)/fuzz/corpus-$$t || exit 1; \
	done

clean:
	rm -rf $(BUILD) $(NAME)-$(VERSION).tar.gz
	rm -rf selinux/tmp selinux/*.pp selinux/*.fc.tmp
