cmake_minimum_required(VERSION 3.13)
project(libsignal-react-native-tests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------
# Test 1: Host FFI integration test
# Links against the host-built libsignal_ffi and tests FFI calls.
# ---------------------------------------------------------------

# Find the host-built libsignal_ffi shared library
set(REPO_ROOT "${CMAKE_SOURCE_DIR}/../..")
set(LIBSIGNAL_FFI_DIR "${REPO_ROOT}/target/debug")
set(SIGNAL_FFI_HEADER_DIR "${CMAKE_SOURCE_DIR}/../cpp")

add_library(signal_ffi_host SHARED IMPORTED)
set_target_properties(signal_ffi_host PROPERTIES
    IMPORTED_LOCATION "${LIBSIGNAL_FFI_DIR}/libsignal_ffi.so"
)

add_executable(test_ffi_host test_ffi_host.cpp)
target_include_directories(test_ffi_host PRIVATE "${SIGNAL_FFI_HEADER_DIR}")
target_link_libraries(test_ffi_host signal_ffi_host pthread dl)

# Set RPATH so the test finds the .so at runtime
set_target_properties(test_ffi_host PROPERTIES
    BUILD_RPATH "${LIBSIGNAL_FFI_DIR}"
    INSTALL_RPATH "${LIBSIGNAL_FFI_DIR}"
)

# ---------------------------------------------------------------
# Test 2: C++ compilation check for JSI bindings
# Syntax-only check that all generated C++ code compiles.
# ---------------------------------------------------------------

# This requires React Native JSI headers.
# Check if they're available (from npm install in react-native/).
set(RN_DIR "${CMAKE_SOURCE_DIR}/..")
set(JSI_DIR "${RN_DIR}/node_modules/react-native/ReactCommon/jsi")

if(EXISTS "${JSI_DIR}/jsi/jsi.h")
    # Create a library target just for compilation checking (won't link)
    add_library(check_jsi_compilation OBJECT
        "${RN_DIR}/cpp/LibsignalTurboModule.cpp"
        "${RN_DIR}/cpp/generated_jsi_bindings.cpp"
    )
    target_include_directories(check_jsi_compilation PRIVATE
        "${RN_DIR}/cpp"
        "${JSI_DIR}"
    )
    message(STATUS "JSI headers found - C++ compilation check enabled")
else()
    message(STATUS "JSI headers not found (run 'npm install' in react-native/) - skipping C++ compilation check")
endif()
