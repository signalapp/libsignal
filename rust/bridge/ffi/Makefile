CONFIG ?= debug

TARGET_DIR := target/$(CARGO_BUILD_TARGET)/$(CONFIG)

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

cbindgen: $(TARGET_DIR)/signal_ffi.h

target/%/signal_ffi.h: signal_ffi.h
	cp $^ $@

signal_ffi.h: src/*.rs Cargo.toml cbindgen.toml
	unset CARGO_BUILD_TARGET && rustup run nightly cbindgen -o $@

pkg-config: $(TARGET_DIR)/signal_ffi.pc

target/%/signal_ffi.pc: signal_ffi.pc
	cp $^ $@

.PHONY: default clean rust cbindgen pkg-config