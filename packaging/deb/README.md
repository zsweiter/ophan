Debian package files used by `cargo deb -p ophan`.

`ophan.service` is generated from `stubs/systemd.service` by `make package-deb` (and by the
release workflow) before packaging, so the stub stays the single source of the unit.
