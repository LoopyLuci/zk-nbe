PREFIX  ?= /usr
DESTDIR ?=
BIN     := target/release
UNITDIR ?= $(PREFIX)/lib/systemd/system

.PHONY: build test install install-server install-client luks-e2e

build:
	cargo build --release

test:
	cargo test --workspace

luks-e2e: build
	scripts/luks-e2e.sh

install: install-server install-client

install-server:
	install -D -m 0755 $(BIN)/zknbed   $(DESTDIR)$(PREFIX)/bin/zknbed
	install -D -m 0755 $(BIN)/zknbectl $(DESTDIR)$(PREFIX)/bin/zknbectl
	install -D -m 0644 dist/systemd/zknbed.service $(DESTDIR)$(UNITDIR)/zknbed.service
	install -D -m 0644 dist/config/zknbed.toml $(DESTDIR)/usr/share/doc/zknbe/zknbed.toml.example

install-client:
	install -D -m 0755 $(BIN)/zknbe $(DESTDIR)$(PREFIX)/bin/zknbe
	install -D -m 0644 dist/systemd/zknbe-agent.service   $(DESTDIR)$(UNITDIR)/zknbe-agent.service
	install -D -m 0644 dist/systemd/zknbe-askpass.path    $(DESTDIR)$(UNITDIR)/zknbe-askpass.path
	install -D -m 0644 dist/systemd/zknbe-askpass.service $(DESTDIR)$(UNITDIR)/zknbe-askpass.service
	install -D -m 0755 dist/initramfs-tools/keyscript     $(DESTDIR)$(PREFIX)/lib/zknbe/keyscript
	install -d $(DESTDIR)$(PREFIX)/lib/dracut/modules.d/60zknbe
	install -m 0755 dist/dracut/60zknbe/module-setup.sh   $(DESTDIR)$(PREFIX)/lib/dracut/modules.d/60zknbe/
	install -m 0644 dist/dracut/60zknbe/zknbe-askpass.*   $(DESTDIR)$(PREFIX)/lib/dracut/modules.d/60zknbe/
