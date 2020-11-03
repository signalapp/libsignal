.PHONY: android_libs desktop_libs

ANDROID_LIB_DIR=android/src/main/jniLibs
DESKTOP_LIB_DIR=java/src/main/resources
OUTPUT_DIR=../target

#RUSTFLAGS="-C link-args-s"
RUSTFLAGS=""

all: android_libs desktop_libs

android_libs: $(ANDROID_LIB_DIR)/armeabi-v7a/libsignal_jni.so \
	$(ANDROID_LIB_DIR)/arm64-v8a/libsignal_jni.so \
	$(ANDROID_LIB_DIR)/x86/libsignal_jni.so \
	$(ANDROID_LIB_DIR)/x86_64/libsignal_jni.so

#desktop_libs: $(DESKTOP_LIB_DIR)/libsignal_jni.so $(DESKTOP_LIB_DIR)/libsignal_jni.dylib $(DESKTOP_LIB_DIR)/libsignal_jni.dll
desktop_libs: $(DESKTOP_LIB_DIR)/libsignal_jni.so

$(DESKTOP_LIB_DIR)/libsignal_jni.so:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo build --target x86_64-unknown-linux-gnu --release
	mkdir -p $(DESKTOP_LIB_DIR)
	cp $(OUTPUT_DIR)/x86_64-unknown-linux-gnu/release/libsignal_jni.so $(DESKTOP_LIB_DIR)

$(DESKTOP_LIB_DIR)/libsignal_jni.dylib:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo build --target x86_64-apple-darwin --release
	mkdir -p $(DESKTOP_LIB_DIR)
	cp target/x86_64-apple-darwin/release/libsignal_jni.dylib $(DESKTOP_LIB_DIR)

$(DESKTOP_LIB_DIR)/libsignal_jni.dll:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo build --target x86_64-pc-windows-msvc --release
	mkdir -p $(DESKTOP_LIB_DIR)
	cp target/x86_64-apple-darwin/release/libsignal_jni.dll $(DESKTOP_LIB_DIR)

$(ANDROID_LIB_DIR)/armeabi-v7a/libsignal_jni.so:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo ndk --target armv7-linux-androideabi --platform 19 -- build --release
	mkdir -p $(ANDROID_LIB_DIR)/armeabi-v7a/
	cp $(OUTPUT_DIR)/armv7-linux-androideabi/release/libsignal_jni.so $(ANDROID_LIB_DIR)/armeabi-v7a/

$(ANDROID_LIB_DIR)/arm64-v8a/libsignal_jni.so:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo ndk --target aarch64-linux-android --platform 21 -- build --release
	mkdir -p $(ANDROID_LIB_DIR)/arm64-v8a
	cp $(OUTPUT_DIR)/aarch64-linux-android/release/libsignal_jni.so $(ANDROID_LIB_DIR)/arm64-v8a

$(ANDROID_LIB_DIR)/x86/libsignal_jni.so:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo ndk --target i686-linux-android --platform 19 -- build --release
	mkdir -p $(ANDROID_LIB_DIR)/x86
	cp $(OUTPUT_DIR)/i686-linux-android/release/libsignal_jni.so $(ANDROID_LIB_DIR)/x86

$(ANDROID_LIB_DIR)/x86_64/libsignal_jni.so:
	cd ../rust/bridge/jni && RUSTFLAGS=$(RUSTFLAGS) cargo ndk --target x86_64-linux-android --platform 21 -- build --release
	mkdir -p $(ANDROID_LIB_DIR)/x86_64
	cp $(OUTPUT_DIR)/x86_64-linux-android/release/libsignal_jni.so $(ANDROID_LIB_DIR)/x86_64

clean:
	rm -f $(ANDROID_LIB_DIR)/x86_64/libsignal_jni.so
	rm -f $(ANDROID_LIB_DIR)/x86/libsignal_jni.so
	rm -f $(ANDROID_LIB_DIR)/arm64-v8a/libsignal_jni.so
	rm -f $(ANDROID_LIB_DIR)/armeabi-v7a/libsignal_jni.so
	rm -f $(DESKTOP_LIB_DIR)/libsignal_jni.dll
	rm -f $(DESKTOP_LIB_DIR)/libsignal_jni.dylib
	rm -f $(DESKTOP_LIB_DIR)/libsignal_jni.so
