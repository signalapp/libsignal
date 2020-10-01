CONFIG ?= debug

ifeq ($(CONFIG),debug)
  CARGO_CONFIG_FLAG :=
else ifeq ($(CONFIG),release)
  CARGO_CONFIG_FLAG := --release
else
  $(error CONFIG can be "debug" or "release" (defaults to "debug"))
endif


default: rust cbindgen pkg-config

clean:
	cargo clean

rust: src/*.rs Cargo.toml
	cargo build $(CARGO_CONFIG_FLAG)

cbindgen: target/$(CONFIG)/signal_ffi.h

target/%/signal_ffi.h: signal_ffi.h
	cp $^ $@

signal_ffi.h: src/*.rs Cargo.toml cbindgen.toml
	rustup run nightly cbindgen -o $@

pkg-config: target/$(CONFIG)/signal_ffi.pc

target/%/signal_ffi.pc: signal_ffi.pc.in
	echo build_dir=$(CURDIR)/target/$(CONFIG) > $@
	cat $^ >> $@

.PHONY: default clean rust cbindgen pkg-config