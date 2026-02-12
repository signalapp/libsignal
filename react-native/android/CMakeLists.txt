cmake_minimum_required(VERSION 3.13)
project(libsignal-react-native)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find React Native (provides JSI headers and library)
find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)

# Locate the prebuilt libsignal_ffi shared library.
# When building, the Rust cross-compiled .so files should be placed under:
#   react-native/android/jniLibs/${ANDROID_ABI}/libsignal_ffi.so
set(LIBSIGNAL_FFI_DIR "${CMAKE_SOURCE_DIR}/jniLibs/${ANDROID_ABI}")

add_library(signal_ffi SHARED IMPORTED)
set_target_properties(signal_ffi PROPERTIES
    IMPORTED_LOCATION "${LIBSIGNAL_FFI_DIR}/libsignal_ffi.so"
    IMPORTED_NO_SONAME TRUE
)

# Our C++ source files
set(CPP_DIR "${CMAKE_SOURCE_DIR}/../cpp")

add_library(${PROJECT_NAME} SHARED
    "${CMAKE_SOURCE_DIR}/src/main/cpp/jni_install.cpp"
    "${CPP_DIR}/LibsignalTurboModule.cpp"
    "${CPP_DIR}/generated_jsi_bindings.cpp"
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CPP_DIR}"
    # signal_ffi.h location — copied into cpp/ during build
    "${CPP_DIR}"
)

target_link_libraries(${PROJECT_NAME}
    signal_ffi
    ReactAndroid::jsi
    ReactAndroid::reactnative
    fbjni::fbjni
    android
    log
)
