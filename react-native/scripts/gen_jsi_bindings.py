#!/usr/bin/env python3
"""
Generate C++ JSI bindings from signal_ffi.h.

Parses the C header file produced by cbindgen and generates C++ code that
registers each signal_* function as a JSI HostObject property, performing
type marshaling between JSI values and C FFI types.

Usage:
    python gen_jsi_bindings.py <path/to/signal_ffi.h> <output.cpp>
"""

import re
import sys
import os
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Param:
    type: str          # full C type string
    name: str
    is_out: bool       # true if this is an output parameter (first param, pointer-to-pointer or pointer-to-scalar)
    is_const: bool
    category: str      # 'buffer', 'string', 'pointer', 'scalar', 'bool', 'uuid', 'fixed_array', 'borrowed_buffer',
                       # 'mut_pointer', 'const_pointer', 'promise', 'store', 'callback_struct', 'borrowed_mutable_buffer',
                       # 'bytestring_array', 'slice_of_buffers', 'slice_of_pointers', 'other'


@dataclass
class FfiFunction:
    name: str                          # e.g. signal_privatekey_generate
    js_name: str                       # e.g. PrivateKey_Generate
    returns_error: bool                # true if return type is SignalFfiError*
    return_type: str                   # actual return type string
    params: list                       # list of Param
    is_async: bool                     # true if has a CPromise parameter
    is_void_return: bool               # true if return type is void
    is_destroy: bool                   # true if this is a _destroy function
    is_clone: bool                     # true if this is a _clone function
    has_store_params: bool             # true if any param is a store callback struct
    skipped: bool = False
    skip_reason: str = ""


# ---------------------------------------------------------------------------
# C name → JS name mapping
# ---------------------------------------------------------------------------

# Functions where the FFI C name differs from the Node.js JS name.
# These come from bridge_handle_fns!(Name, ffi = different_name) and
# bridge_fn(ffi = "different_name") / bridge_fn(ffi = "...", node = "...") in Rust.
# Key: C function name (without 'signal_' prefix). Value: Node-compatible JS name.
FFI_NAME_OVERRIDES = {
    # From bridge_handle_fns!(ProtocolAddress, ffi = address)
    'address_new': 'ProtocolAddress_New',
    'address_get_device_id': 'ProtocolAddress_DeviceId',
    'address_get_name': 'ProtocolAddress_Name',
    # From bridge_handle_fns!(PrivateKey, ffi = privatekey)
    'privatekey_generate': 'PrivateKey_Generate',
    'privatekey_deserialize': 'PrivateKey_Deserialize',
    'privatekey_serialize': 'PrivateKey_Serialize',
    'privatekey_get_public_key': 'PrivateKey_GetPublicKey',
    'privatekey_sign': 'PrivateKey_Sign',
    'privatekey_agree': 'PrivateKey_Agree',
    'privatekey_hpke_open': 'PrivateKey_HpkeOpen',
    # From bridge_handle_fns!(PublicKey, ffi = publickey)
    'publickey_deserialize': 'PublicKey_Deserialize',
    'publickey_serialize': 'PublicKey_Serialize',
    'publickey_get_public_key_bytes': 'PublicKey_GetPublicKeyBytes',
    'publickey_equals': 'PublicKey_Equals',
    'publickey_verify': 'PublicKey_Verify',
    'publickey_hpke_seal': 'PublicKey_HpkeSeal',
    # From bridge_handle_fns!(SignalMessage, ffi = message)
    'message_deserialize': 'SignalMessage_Deserialize',
    'message_get_body': 'SignalMessage_GetBody',
    'message_get_counter': 'SignalMessage_GetCounter',
    'message_get_message_version': 'SignalMessage_GetMessageVersion',
    'message_get_pq_ratchet': 'SignalMessage_GetPqRatchet',
    'message_get_serialized': 'SignalMessage_GetSerialized',
    'message_new': 'SignalMessage_New',
    'message_verify_mac': 'SignalMessage_VerifyMac',
    # From bridge_handle_fns!(Fingerprint) + bridge_fn(ffi = "fingerprint_compare")
    'fingerprint_compare': 'ScannableFingerprint_Compare',
    # From bridge_fn with custom ffi names
    'identitykeypair_serialize': 'IdentityKeyPair_Serialize',
    'identitykeypair_deserialize': 'IdentityKeyPair_Deserialize',
    'identitykeypair_sign_alternate_identity': 'IdentityKeyPair_SignAlternateIdentity',
    'identitykey_verify_alternate_identity': 'IdentityKey_VerifyAlternateIdentity',
    'encrypt_message': 'SessionCipher_EncryptMessage',
    'decrypt_message': 'SessionCipher_DecryptSignalMessage',
    'decrypt_pre_key_message': 'SessionCipher_DecryptPreKeySignalMessage',
    'process_prekey_bundle': 'SessionBuilder_ProcessPreKeyBundle',
    'group_encrypt_message': 'GroupCipher_EncryptMessage',
    'group_decrypt_message': 'GroupCipher_DecryptMessage',
    'username_link_create': 'UsernameLink_CreateAllowingEmptyEntropy',
}


def c_name_to_js_name(c_name: str) -> str:
    """Convert signal_foo_bar_baz to Foo_BarBaz (matching the Node bridge naming)."""
    # Strip 'signal_' prefix
    if c_name.startswith("signal_"):
        name = c_name[len("signal_"):]
    else:
        return c_name

    # Check hardcoded overrides first
    if name in FFI_NAME_OVERRIDES:
        return FFI_NAME_OVERRIDES[name]

    # The JS names use PascalCase with underscores separating "object" from "method"
    # e.g. signal_privatekey_generate -> PrivateKey_Generate
    #      signal_pre_key_bundle_new -> PreKeyBundle_New
    #      signal_aes256_gcm_siv_new -> Aes256GcmSiv_New
    # This is tricky because the C names are fully snake_case.
    # We rely on the known JS names from Native.ts instead.
    return name


# ---------------------------------------------------------------------------
# Type classification
# ---------------------------------------------------------------------------

# Wrapper struct types (MutPointer / ConstPointer) pattern
MUT_POINTER_RE = re.compile(r'Signal(MutPointer\w+)')
CONST_POINTER_RE = re.compile(r'Signal(ConstPointer\w+)')

def classify_param(param_type: str, param_name: str, is_first: bool) -> tuple:
    """Classify a parameter type into a category. Returns (category, is_out, is_const)."""
    t = param_type.strip()

    # Output parameters: first param is pointer-to-something
    # e.g. SignalMutPointerPrivateKey *out, SignalOwnedBuffer *out, const char **out
    # bool *out, uint32_t *out, uint64_t *out

    is_out = False
    is_const = 'const ' in t

    # Promise types -> async
    if 'SignalCPromise' in t:
        return ('promise', True, False)

    # Store / callback struct types
    if 'StoreStruct' in t or 'ListenerStruct' in t or 'ConnectChatBridgeStruct' in t:
        return ('callback_struct', False, is_const)

    # SignalFfiLogger
    if 'SignalFfiLogger' in t:
        return ('callback_struct', False, False)

    # SignalBorrowedBuffer
    if t == 'SignalBorrowedBuffer':
        return ('borrowed_buffer', False, False)

    # SignalBorrowedMutableBuffer
    if t == 'SignalBorrowedMutableBuffer':
        return ('borrowed_mutable_buffer', False, False)

    # SignalOwnedBuffer *out (but NOT SignalOwnedBufferOfFfi* which are typed buffers)
    if 'SignalOwnedBuffer' in t and '*' in t and 'SignalOwnedBufferOf' not in t:
        return ('buffer', True, False)

    # SignalBytestringArray *out
    if 'SignalBytestringArray' in t and '*' in t:
        return ('bytestring_array', True, False)
    if 'SignalStringArray' in t and '*' in t:
        return ('bytestring_array', True, False)

    # SignalBorrowedBytestringArray
    if 'SignalBorrowedBytestringArray' in t:
        return ('bytestring_array', False, False)

    # SignalBorrowedSliceOfBuffers
    if 'SignalBorrowedSliceOfBuffers' in t:
        return ('slice_of_buffers', False, False)

    # SignalBorrowedSliceOfConst*
    if 'SignalBorrowedSliceOf' in t:
        return ('slice_of_pointers', False, False)

    # const char **out (pointer to pointer — output string)
    if t == 'const char **' or t == 'const char * *':
        return ('string', True, True)

    # const char * (input string)
    if t == 'const char *':
        return ('string', False, True)

    # SignalMutPointer* *out (pointer to MutPointer -> output pointer)
    if re.match(r'SignalMutPointer\w+ \*', t):
        return ('mut_pointer', True, False)

    # SignalMutPointer (by value, e.g. destroy functions)
    if re.match(r'SignalMutPointer\w+$', t):
        return ('mut_pointer', False, False)

    # SignalConstPointer*
    if re.match(r'SignalConstPointer\w+', t):
        return ('const_pointer', False, True)

    # Fixed-size array outputs: uint8_t (*out)[N], unsigned char (*out)[N]
    if re.search(r'\(\*\w+\)\[', t):
        return ('fixed_array', True, False)

    # SignalServiceIdFixedWidthBinaryBytes *out (non-const)
    if 'SignalServiceIdFixedWidthBinaryBytes' in t and '*' in t and 'const' not in t:
        return ('fixed_array', True, False)

    # const SignalServiceIdFixedWidthBinaryBytes *
    if 'SignalServiceIdFixedWidthBinaryBytes' in t:
        return ('fixed_array', False, True)

    # SignalUuid
    if 'SignalUuid' in t and '*' not in t:
        return ('uuid', False, False)
    if 'SignalUuid' in t and '*' in t:
        return ('uuid', True, False)

    # SignalOptional*
    if 'SignalOptional' in t and '*' in t:
        return ('other', True, False)
    if 'SignalOptional' in t:
        return ('other', False, False)

    # bool *out
    if t == 'bool *' or (t.startswith('bool') and '*' in t):
        return ('bool', True, False)

    # bool (by value)
    if t == 'bool':
        return ('bool', False, False)

    # Scalar output: uint8_t *, uint16_t *, uint32_t *, uint64_t *, int32_t *, size_t *
    if re.match(r'(u?int\d+_t|size_t|double)\s*\*', t):
        return ('scalar', True, False)

    # Scalar by value
    if re.match(r'(u?int\d+_t|size_t|uint8_t|uint16_t|uint32_t|uint64_t|int32_t|double)$', t):
        return ('scalar', False, False)

    # void *
    if t == 'void *' or t == 'const void *':
        return ('other', False, False)

    # SignalFfiError * (return type handling, or input to error inspection functions)
    if 'SignalFfiError' in t or 'SignalUnwindSafeArg' in t:
        return ('other', False, False)

    # SignalPairOf... (compound return)
    if 'SignalPairOf' in t and '*' in t:
        return ('other', True, False)
    if 'SignalPairOf' in t:
        return ('other', False, False)

    # SignalOwnedBufferOfFfi* — typed owned buffers (not simple byte buffers)
    # e.g. SignalOwnedBufferOfFfiMismatchedDevicesError, SignalOwnedBufferOfFfiRegisterResponseBadge
    if re.match(r'SignalOwnedBufferOfFfi\w+', t.lstrip('const ').rstrip(' *')):
        if '*' in t:
            return ('other', True, False)
        return ('other', False, False)

    # SignalFfiSignedPublicPreKey — complex struct passed by value
    if 'SignalFfiSignedPublicPreKey' in t:
        return ('other', False, False)

    # Fixed-size byte array types passed as pointers:
    # const SignalBackupKeyBytes *, const SignalRandomnessBytes *, const SignalUnidentifiedAccessKey *
    if re.match(r'const\s+Signal\w+Bytes\s*\*$', t) or re.match(r'const\s+SignalUnidentifiedAccessKey\s*\*$', t):
        return ('fixed_array', False, True)

    # SignalFfi* struct by value (e.g. other Signal* types we haven't matched)
    if t.startswith('SignalFfi') or t.startswith('Signal'):
        if '*' in t:
            return ('other', True if is_first else False, is_const)
        return ('other', False, False)

    # Callback function pointers
    if '(*' in t:
        return ('callback_struct', False, False)

    return ('other', False, is_const)


# ---------------------------------------------------------------------------
# Header parser
# ---------------------------------------------------------------------------

def parse_header(header_path: str) -> tuple:
    """Parse signal_ffi.h and extract function declarations and type info."""
    with open(header_path, 'r') as f:
        content = f.read()

    # Extract all function declarations using a two-pass approach:
    # 1. Find function name and return type
    # 2. Extract params by finding the matching );

    func_start_pattern = re.compile(
        r'\n(SignalFfiError\s*\*\s*|void\s+|bool\s+|uint32_t\s+)(signal_\w+)\s*\('
    )

    functions = []
    for match in func_start_pattern.finditer(content):
        ret_type = match.group(1).strip()
        func_name = match.group(2).strip()

        # Find the closing );  starting from after the opening (
        paren_start = match.end()  # position right after the (
        depth = 1
        i = paren_start
        while i < len(content) and depth > 0:
            if content[i] == '(':
                depth += 1
            elif content[i] == ')':
                depth -= 1
            i += 1
        # i is now right after the closing )
        params_str = content[paren_start:i-1].strip()

        returns_error = ret_type == 'SignalFfiError *' or ret_type == 'SignalFfiError*'
        is_void = ret_type == 'void'

        # Parse individual parameters
        params = parse_params(params_str)

        # Determine if async (has CPromise param)
        is_async = any(p.category == 'promise' for p in params)

        # Determine if destroy/clone
        is_destroy = func_name.endswith('_destroy')
        is_clone = func_name.endswith('_clone')

        # Check for store params
        has_store = any(p.category == 'callback_struct' for p in params)

        func = FfiFunction(
            name=func_name,
            js_name='',  # filled in later
            returns_error=returns_error,
            return_type=ret_type,
            params=params,
            is_async=is_async,
            is_void_return=is_void,
            is_destroy=is_destroy,
            is_clone=is_clone,
            has_store_params=has_store,
        )
        functions.append(func)

    # Extract #define constants
    defines = {}
    define_pattern = re.compile(r'^#define\s+(Signal\w+)\s+(.+)$', re.MULTILINE)
    for match in define_pattern.finditer(content):
        defines[match.group(1)] = match.group(2).strip()

    # Extract enum values
    enums = {}
    enum_pattern = re.compile(
        r'typedef\s+enum\s*\{(.*?)\}\s*(\w+)\s*;',
        re.DOTALL
    )
    for match in enum_pattern.finditer(content):
        enum_body = match.group(1)
        enum_name = match.group(2)
        values = re.findall(r'(\w+)\s*=\s*(\d+)', enum_body)
        if not values:
            values = re.findall(r'(\w+)\s*(?:,|})', enum_body)
            values = [(v, str(i)) for i, v in enumerate(values)]
        enums[enum_name] = values

    return functions, defines, enums


def parse_params(params_str: str) -> list:
    """Parse a comma-separated parameter list into Param objects."""
    if not params_str or params_str == 'void':
        return []

    # Split on commas, but respect nested parentheses and brackets
    params = []
    depth = 0
    current = []
    for char in params_str:
        if char in '([':
            depth += 1
            current.append(char)
        elif char in ')]':
            depth -= 1
            current.append(char)
        elif char == ',' and depth == 0:
            params.append(''.join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        params.append(''.join(current).strip())

    result = []
    for i, param_str in enumerate(params):
        param_str = param_str.strip()
        if not param_str:
            continue

        # Extract type and name
        # Handle complex cases like: uint8_t (*out)[32], const unsigned char (*params)[N]
        # Simple cases: SignalMutPointerPrivateKey *out, const char *name, uint32_t device_id

        # Fixed array pattern: type (*name)[size]
        fixed_arr_match = re.match(r'(.+?)\s*\(\*(\w+)\)\s*\[(.+)\]', param_str)
        if fixed_arr_match:
            base_type = fixed_arr_match.group(1).strip()
            name = fixed_arr_match.group(2)
            size = fixed_arr_match.group(3)
            full_type = f'{base_type} (*{name})[{size}]'
            category, is_out, is_const = classify_param(full_type, name, i == 0)
            result.append(Param(type=full_type, name=name, is_out=is_out,
                              is_const=is_const, category=category))
            continue

        # Function pointer pattern: type (*name)(...)
        fptr_match = re.match(r'(.+?)\s*\(\*(\w+)\)\s*\((.+)\)', param_str)
        if fptr_match:
            full_type = param_str[:param_str.rfind(fptr_match.group(2))].strip() + '(*)(' + fptr_match.group(3) + ')'
            name = fptr_match.group(2)
            category, is_out, is_const = classify_param(full_type, name, i == 0)
            result.append(Param(type=full_type, name=name, is_out=is_out,
                              is_const=is_const, category=category))
            continue

        # Pointer-to-pointer: type **name
        pp_match = re.match(r'(.+\*)\s*\*\s*(\w+)', param_str)
        if pp_match and '(' not in param_str:
            ptype = pp_match.group(1).strip() + ' *'
            name = pp_match.group(2)
            category, is_out, is_const = classify_param(ptype, name, i == 0)
            result.append(Param(type=ptype, name=name, is_out=is_out,
                              is_const=is_const, category=category))
            continue

        # Standard: type *name or type name
        # Find the last word as the name
        parts = param_str.rsplit(None, 1)
        if len(parts) == 2:
            ptype = parts[0].strip()
            name = parts[1].strip().lstrip('*')
            if parts[1].startswith('*'):
                ptype += ' *'
        elif len(parts) == 1:
            ptype = parts[0]
            name = f'arg{i}'
        else:
            ptype = param_str
            name = f'arg{i}'

        category, is_out, is_const = classify_param(ptype, name, i == 0)
        result.append(Param(type=ptype, name=name, is_out=is_out,
                          is_const=is_const, category=category))

    return result


# ---------------------------------------------------------------------------
# JS name resolution
# ---------------------------------------------------------------------------

def build_js_name_map(native_ts_path: Optional[str]) -> dict:
    """Build mapping from C function name to JS function name by parsing Native.ts."""
    js_to_c = {}

    # Always include the hardcoded FFI name overrides (reverse map)
    for c_suffix, js_name in FFI_NAME_OVERRIDES.items():
        js_to_c['signal_' + c_suffix] = js_name

    if not native_ts_path or not os.path.exists(native_ts_path):
        return js_to_c

    with open(native_ts_path, 'r') as f:
        content = f.read()

    # Extract function names from the NativeFunctions type definition
    # Matches both "  FunctionName: (...) => Type;" and standalone names
    names = set(re.findall(r'^\s+(\w+)[,:]', content, re.MULTILINE))

    # Build mapping: for each JS name, figure out what C function it maps to
    for js_name in names:
        c_name = js_name_to_c_name(js_name)
        # Don't override explicit FFI name mappings
        if c_name not in js_to_c:
            js_to_c[c_name] = js_name

    return js_to_c


def js_name_to_c_name(js_name: str) -> str:
    """Convert a JS bridge function name to its C FFI counterpart.

    Uses the same algorithm as the Rust `heck` crate's to_snake_case(),
    which is what the bridge_fn macro uses to generate FFI symbol names.
    The FFI prefix 'signal_' is prepended.

    Examples:
        PrivateKey_Generate -> signal_private_key_generate
        Aes256GcmSiv_New -> signal_aes256_gcm_siv_new
        HKDF_DeriveSecrets -> signal_hkdf_derive_secrets

    Note: Some functions have explicit FFI name overrides in Rust
    (e.g., PrivateKey_Generate -> signal_privatekey_generate), which
    means this computed name may not match the actual C function name.
    The caller uses fuzzy matching as a fallback.
    """
    # Implement heck's to_snake_case algorithm
    result = []
    prev_was_upper = False
    prev_was_underscore = True  # treat start as after underscore

    for i, char in enumerate(js_name):
        if char == '_':
            if result and result[-1] != '_':
                result.append('_')
            prev_was_upper = False
            prev_was_underscore = True
        elif char.isupper():
            next_is_lower = (i + 1 < len(js_name) and js_name[i + 1].islower())
            if not prev_was_underscore:
                if not prev_was_upper:
                    # lowercase -> uppercase: new word
                    result.append('_')
                elif next_is_lower:
                    # end of acronym run: new word (e.g., "GcmS" -> "gcm_s")
                    result.append('_')
            result.append(char.lower())
            prev_was_upper = True
            prev_was_underscore = False
        elif char.isdigit():
            result.append(char)
            prev_was_upper = False
            prev_was_underscore = False
        else:
            result.append(char)
            prev_was_upper = False
            prev_was_underscore = False

    c_name = 'signal_' + ''.join(result)
    return c_name


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------

def determine_skipped(func: FfiFunction) -> tuple:
    """Determine if a function should be skipped and why."""
    # Skip testing functions
    if 'TESTING' in func.name or 'testing' in func.name.lower() or 'test_only' in func.name:
        return True, "testing function"

    # Skip destroy/clone (handled separately by pointer wrapper)
    if func.is_destroy:
        return True, "destroy function (handled by pointer destructor)"

    if func.is_clone:
        return True, "clone function (handled by pointer wrapper)"

    # Skip functions with complex callback struct params (stores, listeners)
    # These need special hand-written implementations
    if func.has_store_params:
        return True, "has callback struct params (needs hand-written implementation)"

    # Skip free functions
    if func.name.startswith('signal_free_'):
        return True, "free function (handled internally)"

    # Skip error inspection functions — these are internal helpers used by
    # checkError(), not meant to be called from JS
    if func.name.startswith('signal_error_'):
        return True, "error inspection function (used internally by checkError)"

    # Skip print/debug functions
    if func.name == 'signal_print_ptr':
        return True, "debug function"

    # Skip init_logger (needs special callback handling)
    if func.name == 'signal_init_logger':
        return True, "logger init (needs hand-written implementation)"

    # Skip media sanitizer functions (signal-media feature not enabled by default)
    if any(x in func.name for x in ['mp4_sanitizer', 'webp_sanitizer', 'sanitized_metadata', 'signal_media_check']):
        return True, "media sanitizer (requires signal-media feature)"

    # Skip functions that have any 'other' category parameters we can't convert
    for p in func.params:
        if p.category == 'other' and not p.is_out:
            return True, f"has unconvertible input param: {p.type} {p.name}"
        if p.category == 'other' and p.is_out:
            return True, f"has unconvertible output param: {p.type} {p.name}"

    return False, ""


def get_out_params(func: FfiFunction) -> list:
    """Get the output parameters of a function."""
    return [p for p in func.params if p.is_out]


def get_in_params(func: FfiFunction) -> list:
    """Get the input parameters of a function."""
    return [p for p in func.params if not p.is_out]


def gen_sync_wrapper(func: FfiFunction) -> str:
    """Generate C++ code for a synchronous FFI function wrapper."""
    lines = []
    out_params = get_out_params(func)
    in_params = get_in_params(func)

    lines.append(f'    // {func.name}')
    lines.append(f'    functions_["{func.js_name}"] = [](jsi::Runtime& rt,')
    lines.append(f'            const jsi::Value& /*thisVal*/, const jsi::Value* args, size_t count) -> jsi::Value {{')

    # Declare output variables
    for p in out_params:
        decl = gen_out_declaration(p)
        if decl:
            lines.append(f'        {decl}')

    # Convert input arguments from JSI
    arg_idx = 0
    arg_conversions = []
    call_args = []

    for p in func.params:
        if p.is_out:
            call_args.append(gen_out_call_arg(p))
            continue

        conv, expr = gen_input_conversion(p, arg_idx)
        if conv:
            arg_conversions.extend(conv)
        call_args.append(expr)
        arg_idx += 1

    for conv_line in arg_conversions:
        lines.append(f'        {conv_line}')

    # Call the C function
    call_args_str = ', '.join(call_args)
    if func.returns_error:
        lines.append(f'        checkError(rt, {func.name}({call_args_str}));')
    elif func.is_void_return:
        lines.append(f'        {func.name}({call_args_str});')
    else:
        # Non-error, non-void return (rare - e.g. signal_error_get_type returns uint32_t)
        lines.append(f'        auto result = {func.name}({call_args_str});')

    # Convert output to JSI return value
    if out_params:
        ret = gen_return_conversion(out_params[0], func)
        lines.append(f'        {ret}')
    elif not func.is_void_return and not func.returns_error:
        lines.append(f'        return jsi::Value(static_cast<double>(result));')
    else:
        lines.append(f'        return jsi::Value::undefined();')

    lines.append(f'    }};')
    lines.append('')

    return '\n'.join(lines)


def gen_out_declaration(param: Param) -> str:
    """Generate C++ declaration for an output parameter."""
    t = param.type

    if param.category == 'mut_pointer':
        # e.g. SignalMutPointerPrivateKey *out -> SignalMutPointerPrivateKey out = {nullptr};
        base_type = t.rstrip(' *').strip()
        return f'{base_type} {param.name} = {{nullptr}};'

    if param.category == 'buffer':
        return f'SignalOwnedBuffer {param.name} = {{nullptr, 0}};'

    if param.category == 'bytestring_array':
        if 'SignalStringArray' in t:
            return f'SignalStringArray {param.name} = {{}};'
        return f'SignalBytestringArray {param.name} = {{}};'

    if param.category == 'string':
        return f'const char* {param.name} = nullptr;'

    if param.category == 'bool':
        return f'bool {param.name} = false;'

    if param.category == 'scalar':
        # Extract the scalar type
        scalar_type = t.rstrip(' *').strip()
        return f'{scalar_type} {param.name} = 0;'

    if param.category == 'fixed_array':
        # e.g. uint8_t (*out)[32] -> uint8_t out[32] = {0};
        arr_match = re.search(r'\(\*\w+\)\[(.+)\]', t)
        if arr_match:
            size = arr_match.group(1)
            base = t.split('(')[0].strip()
            return f'{base} {param.name}[{size}] = {{0}};'
        if 'SignalServiceIdFixedWidthBinaryBytes' in t:
            return f'SignalServiceIdFixedWidthBinaryBytes {param.name} = {{0}};'
        return f'// TODO: {t} {param.name}'

    if param.category == 'uuid':
        return f'SignalUuid {param.name} = {{{{0}}}};'

    if param.category == 'promise':
        base_type = t.rstrip(' *').strip()
        return f'{base_type} {param.name} = {{}};'

    if param.category == 'other':
        base_type = t.rstrip(' *').strip()
        return f'{base_type} {param.name} = {{}};'

    return f'// TODO: {t} {param.name}'


def gen_out_call_arg(param: Param) -> str:
    """Generate the argument expression for an output parameter in the C call."""
    if param.category in ('mut_pointer', 'buffer', 'bytestring_array', 'promise', 'other'):
        return f'&{param.name}'
    if param.category == 'string':
        return f'&{param.name}'
    if param.category in ('bool', 'scalar'):
        return f'&{param.name}'
    if param.category == 'fixed_array':
        if 'SignalServiceIdFixedWidthBinaryBytes' in param.type:
            return f'&{param.name}'
        return f'&{param.name}'
    if param.category == 'uuid':
        return f'&{param.name}'
    return f'&{param.name}'


def gen_input_conversion(param: Param, arg_idx: int) -> tuple:
    """Generate input conversion code. Returns (list_of_lines, call_expression)."""
    t = param.type
    var = f'arg{arg_idx}_val'

    if param.category == 'borrowed_buffer':
        return (
            [f'auto {var} = jsiToBuffer(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'borrowed_mutable_buffer':
        return (
            [f'auto {var} = jsiToMutableBuffer(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'string':
        return (
            [f'auto {var} = jsiToString(rt, args[{arg_idx}]);'],
            f'{var}.c_str()'
        )

    if param.category == 'const_pointer':
        # Extract the pointer type
        base = t.strip()
        return (
            [f'{base} {var} = jsiToConstPointer<{base}>(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'mut_pointer':
        base = t.strip()
        return (
            [f'{base} {var} = jsiToMutPointer<{base}>(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'scalar':
        return (
            [],
            f'static_cast<{t}>(args[{arg_idx}].asNumber())'
        )

    if param.category == 'bool':
        return (
            [],
            f'args[{arg_idx}].getBool()'
        )

    if param.category == 'uuid':
        return (
            [f'auto {var} = jsiToUuid(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'fixed_array':
        # const unsigned char (*params)[N] or const SignalServiceIdFixedWidthBinaryBytes *
        if 'SignalServiceIdFixedWidthBinaryBytes' in t:
            return (
                [f'SignalServiceIdFixedWidthBinaryBytes {var}_buf = {{0}};',
                 f'jsiToServiceId(rt, args[{arg_idx}], {var}_buf);'],
                f'&{var}_buf'
            )
        # const SignalBackupKeyBytes *, const SignalRandomnessBytes *, const SignalUnidentifiedAccessKey *
        # These are typedefs for fixed-size uint8_t arrays
        fixed_type_match = re.match(r'const\s+(Signal\w+)\s*\*$', t)
        if fixed_type_match:
            fixed_type = fixed_type_match.group(1)
            return (
                [f'{fixed_type} {var}_buf = {{0}};',
                 f'auto {var}_src = jsiToBuffer(rt, args[{arg_idx}]);',
                 f'std::memcpy({var}_buf, {var}_src.base, std::min({var}_src.length, sizeof({fixed_type})));'],
                f'&{var}_buf'
            )
        # Generic fixed array: uint8_t (*out)[N]
        return (
            [f'auto {var} = jsiToFixedBuffer(rt, args[{arg_idx}]);'],
            f'reinterpret_cast<decltype(std::declval<{t.split("(")[0].strip()}>())>({var}.data())'
        )

    if param.category == 'bytestring_array':
        return (
            [f'auto {var} = jsiToBytestringArray(rt, args[{arg_idx}]);'],
            f'{var}'
        )

    if param.category == 'slice_of_buffers':
        return (
            [f'auto {var} = jsiToSliceOfBuffers(rt, args[{arg_idx}]);'],
            f'{var}.slice'
        )

    if param.category == 'slice_of_pointers':
        # Extract the base type from the parameter type
        # e.g. SignalBorrowedSliceOfConstPointerPublicKey
        base = t.strip()
        return (
            [f'auto {var} = jsiToSliceOfPointers<{base}>(rt, args[{arg_idx}]);'],
            f'{var}.slice'
        )

    # Fallback
    return (
        [f'// TODO: convert {param.category} type {t} for {param.name}'],
        f'/* {param.name} */'
    )


def gen_return_conversion(param: Param, func: FfiFunction) -> str:
    """Generate code to convert an output parameter to a JSI return value."""
    if param.category == 'mut_pointer':
        # Return as a NativePointer HostObject
        # Extract the underlying type name for the destroy function
        base = param.type.rstrip(' *').strip()
        # Derive destroy function name
        # e.g. SignalMutPointerPrivateKey -> signal_privatekey_destroy
        return f'return pointerToJsi(rt, {param.name});'

    if param.category == 'buffer':
        return f'return ownedBufferToJsi(rt, {param.name});'

    if param.category == 'bytestring_array':
        return f'return bytestringArrayToJsi(rt, {param.name});'

    if param.category == 'string':
        return f'return stringToJsi(rt, {param.name});'

    if param.category == 'bool':
        return f'return jsi::Value({param.name});'

    if param.category == 'scalar':
        return f'return jsi::Value(static_cast<double>({param.name}));'

    if param.category == 'fixed_array':
        arr_match = re.search(r'\[(.+)\]', param.type)
        if arr_match:
            size = arr_match.group(1)
            return f'return fixedArrayToJsi(rt, {param.name}, {size});'
        if 'SignalServiceIdFixedWidthBinaryBytes' in param.type:
            return f'return fixedArrayToJsi(rt, {param.name}, sizeof(SignalServiceIdFixedWidthBinaryBytes));'
        return f'// TODO: return fixed array'

    if param.category == 'uuid':
        return f'return uuidToJsi(rt, {param.name});'

    if param.category == 'other':
        return f'// TODO: return {param.type}\n        return jsi::Value::undefined();'

    return f'return jsi::Value::undefined();'


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def generate_bindings(header_path: str, native_ts_path: Optional[str], output_path: str):
    """Generate the full C++ bindings file."""
    functions, defines, enums = parse_header(header_path)
    js_name_map = build_js_name_map(native_ts_path)

    # Build reverse map: c_name -> js_name
    c_to_js = {}
    for c_name, js_name in js_name_map.items():
        c_to_js[c_name] = js_name

    # Also try matching by normalizing both sides
    c_name_normalized = {}
    for func in functions:
        normalized = func.name.replace('signal_', '').replace('_', '').lower()
        c_name_normalized[normalized] = func.name

    js_normalized = {}
    for c_name, js_name in js_name_map.items():
        normalized = js_name.replace('_', '').lower()
        js_normalized[normalized] = js_name

    # Assign JS names
    unmatched = []
    for func in functions:
        if func.name in c_to_js:
            func.js_name = c_to_js[func.name]
        else:
            # Try normalized matching
            norm = func.name.replace('signal_', '').replace('_', '').lower()
            if norm in js_normalized:
                func.js_name = js_normalized[norm]
            else:
                # Generate a reasonable JS name from the C name
                func.js_name = c_name_to_reasonable_js(func.name)
                unmatched.append(func.name)

        # Check if should be skipped
        func.skipped, func.skip_reason = determine_skipped(func)

    # Separate sync vs async
    sync_funcs = [f for f in functions if not f.skipped and not f.is_async]
    async_funcs = [f for f in functions if not f.skipped and f.is_async]
    skipped_funcs = [f for f in functions if f.skipped]

    # Generate output
    with open(output_path, 'w') as f:
        f.write(GENERATED_HEADER)
        f.write('\n')

        # Stats comment
        f.write(f'// Total functions found: {len(functions)}\n')
        f.write(f'// Synchronous bindings generated: {len(sync_funcs)}\n')
        f.write(f'// Async bindings generated: {len(async_funcs)}\n')
        f.write(f'// Skipped: {len(skipped_funcs)}\n')
        if unmatched:
            f.write(f'// Unmatched C names (using generated JS name): {len(unmatched)}\n')
        f.write('\n')

        f.write('namespace libsignal {\n\n')
        f.write('void LibsignalModule::registerGeneratedFunctions(jsi::Runtime& rt) {\n\n')

        # Sync functions
        f.write('    // ============================================================\n')
        f.write('    // Synchronous functions\n')
        f.write('    // ============================================================\n\n')

        for func in sync_funcs:
            f.write(gen_sync_wrapper(func))

        # Async functions (generate with TODO markers)
        f.write('\n    // ============================================================\n')
        f.write('    // Async functions (CPromise-based)\n')
        f.write('    // These require background thread + Promise resolution.\n')
        f.write('    // ============================================================\n\n')

        for func in async_funcs:
            f.write(gen_async_stub(func))

        f.write('}\n\n')

        # Generate the property names list
        f.write('std::vector<jsi::PropNameID> LibsignalModule::getGeneratedPropertyNames(jsi::Runtime& rt) {\n')
        f.write('    std::vector<jsi::PropNameID> names;\n')
        all_funcs = sync_funcs + async_funcs
        f.write(f'    names.reserve({len(all_funcs)});\n')
        for func in all_funcs:
            f.write(f'    names.push_back(jsi::PropNameID::forAscii(rt, "{func.js_name}"));\n')
        f.write('    return names;\n')
        f.write('}\n\n')

        f.write('} // namespace libsignal\n')

    # Print summary
    print(f"Generated {output_path}")
    print(f"  Total functions in header: {len(functions)}")
    print(f"  Sync bindings: {len(sync_funcs)}")
    print(f"  Async bindings: {len(async_funcs)}")
    print(f"  Skipped: {len(skipped_funcs)}")
    for sf in skipped_funcs[:10]:
        print(f"    - {sf.name}: {sf.skip_reason}")
    if len(skipped_funcs) > 10:
        print(f"    ... and {len(skipped_funcs) - 10} more")
    if unmatched:
        print(f"  Unmatched (generated JS name): {len(unmatched)}")
        for um in unmatched[:5]:
            print(f"    - {um}")


def c_name_to_reasonable_js(c_name: str) -> str:
    """Convert a C function name to a reasonable JS name when no mapping exists."""
    name = c_name
    if name.startswith('signal_'):
        name = name[len('signal_'):]

    # Split on underscores and PascalCase each part
    parts = name.split('_')
    # Try to group parts into "Object" and "Method"
    # Simple heuristic: capitalize each part
    return '_'.join(p.capitalize() for p in parts)


def gen_async_stub(func: FfiFunction) -> str:
    """Generate a full async function implementation using CPromise callbacks."""
    lines = []
    lines.append(f'    // ASYNC: {func.name} -> {func.js_name}')

    # Find the promise parameter to determine the CPromise type
    promise_param = None
    for p in func.params:
        if p.category == 'promise':
            promise_param = p
            break

    if not promise_param:
        lines.append(f'    // ERROR: no promise parameter found for {func.name}')
        lines.append('')
        return '\n'.join(lines)

    # Extract the CPromise type name (e.g., "SignalCPromisebool" from "SignalCPromisebool *")
    promise_type = promise_param.type.replace('*', '').strip()

    # Determine the result conversion code based on CPromise type
    result_conversion = get_promise_result_conversion(promise_type)

    # The lambda captures `this` to access callInvoker_ and asyncContext_
    lines.append(f'    functions_["{func.js_name}"] = [this](jsi::Runtime& rt,')
    lines.append(f'            const jsi::Value& /*thisVal*/, const jsi::Value* args, size_t count) -> jsi::Value {{')
    lines.append(f'        auto ci = callInvoker_;')
    lines.append(f'        return createAsyncCall(rt, args, count, ci, [this, ci]('
                 f'jsi::Runtime& rt, const jsi::Value* args, size_t count,')
    lines.append(f'                PromiseResolver resolver) {{')

    # Allocate resolver on heap so it survives the async callback
    lines.append(f'            auto* resolverPtr = new PromiseResolver(std::move(resolver));')

    # Input conversions (skip promise param and TokioAsyncContext)
    arg_idx = 0
    call_args = []
    for p in func.params:
        if p.category == 'promise':
            call_args.append('&promise')
            continue
        if p.is_out:
            call_args.append(gen_out_call_arg(p))
            continue

        # TokioAsyncContext is provided by the module, not from JS args
        if p.type.strip().startswith('SignalConstPointerTokioAsyncContext'):
            call_args.append('asyncContext_')
            continue

        conv, expr = gen_input_conversion(p, arg_idx)
        if conv:
            for c in conv:
                lines.append(f'            {c}')
        call_args.append(expr)
        arg_idx += 1

    # Set up the CPromise struct with the completion callback
    lines.append(f'            {promise_type} promise = {{}};')
    lines.append(f'            promise.context = reinterpret_cast<const void*>(resolverPtr);')
    lines.append(f'            promise.complete = {result_conversion};')

    # Call the FFI function
    call_str = ', '.join(call_args)
    lines.append(f'            SignalFfiError* err = {func.name}({call_str});')
    lines.append(f'            if (err) {{')
    lines.append(f'                const char* msg = nullptr;')
    lines.append(f'                SignalFfiError* msgErr = signal_error_get_message(&msg, err);')
    lines.append(f'                std::string errorMsg = msg ? msg : "Unknown error";')
    lines.append(f'                if (msg) signal_free_string(msg);')
    lines.append(f'                if (msgErr) signal_error_free(msgErr);')
    lines.append(f'                signal_error_free(err);')
    lines.append(f'                resolverPtr->reject(errorMsg);')
    lines.append(f'                delete resolverPtr;')
    lines.append(f'            }}')
    lines.append(f'        }});')
    lines.append(f'    }};')
    lines.append('')
    return '\n'.join(lines)


# Map CPromise types to their completion callback lambdas.
# The callback runs on a background thread (Rust async runtime) and must
# use the PromiseResolver (which dispatches via CallInvoker) to resolve.

CPROMISE_RESULT_CALLBACKS = {
    'SignalCPromisebool': 'promise_complete_bool',
    'SignalCPromiseMutPointerAuthenticatedChatConnection': 'promise_complete_pointer<SignalMutPointerAuthenticatedChatConnection>',
    'SignalCPromiseMutPointerCdsiLookup': 'promise_complete_pointer<SignalMutPointerCdsiLookup>',
    'SignalCPromiseMutPointerProvisioningChatConnection': 'promise_complete_pointer<SignalMutPointerProvisioningChatConnection>',
    'SignalCPromiseMutPointerRegistrationService': 'promise_complete_pointer<SignalMutPointerRegistrationService>',
    'SignalCPromiseMutPointerRegisterAccountResponse': 'promise_complete_pointer<SignalMutPointerRegisterAccountResponse>',
    'SignalCPromiseMutPointerBackupRestoreResponse': 'promise_complete_pointer<SignalMutPointerBackupRestoreResponse>',
    'SignalCPromiseMutPointerBackupStoreResponse': 'promise_complete_pointer<SignalMutPointerBackupStoreResponse>',
    'SignalCPromiseMutPointerUnauthenticatedChatConnection': 'promise_complete_pointer<SignalMutPointerUnauthenticatedChatConnection>',
    'SignalCPromiseOwnedBufferOfc_uchar': 'promise_complete_buffer',
    'SignalCPromiseOwnedBufferOfServiceIdFixedWidthBinaryBytes': 'promise_complete_service_id_buffer',
    'SignalCPromiseFfiChatResponse': 'promise_complete_opaque<SignalFfiChatResponse>',
    'SignalCPromiseFfiCdsiLookupResponse': 'promise_complete_opaque<SignalFfiCdsiLookupResponse>',
    'SignalCPromiseFfiCheckSvr2CredentialsResponse': 'promise_complete_opaque<SignalFfiCheckSvr2CredentialsResponse>',
    'SignalCPromiseOptionalUuid': 'promise_complete_optional_uuid',
    'SignalCPromiseOptionalPairOfc_charu832': 'promise_complete_optional_pair',
    'SignalCPromisei32': 'promise_complete_i32',
}


def get_promise_result_conversion(promise_type: str) -> str:
    """Get the completion callback function name for a CPromise type."""
    if promise_type in CPROMISE_RESULT_CALLBACKS:
        return CPROMISE_RESULT_CALLBACKS[promise_type]
    # Fallback: try to match MutPointer pattern
    m = re.match(r'SignalCPromiseMutPointer(\w+)', promise_type)
    if m:
        return f'promise_complete_pointer<SignalMutPointer{m.group(1)}>'
    # Unknown type
    return f'/* UNKNOWN PROMISE TYPE: {promise_type} */ nullptr'


GENERATED_HEADER = """\
// AUTO-GENERATED FILE — DO NOT EDIT
// Generated by gen_jsi_bindings.py from signal_ffi.h
//
// This file contains JSI function registrations for all synchronous and
// async FFI functions in libsignal.

#include "LibsignalTurboModule.h"

// ---------------------------------------------------------------
// CPromise completion callbacks
// Called from Rust async runtime (background thread).
// Each extracts the result, then resolves/rejects via PromiseResolver
// (which dispatches to JS thread via CallInvoker).
// ---------------------------------------------------------------

namespace libsignal {

// Helper: reject a promise with an FFI error
static void promise_reject_error(PromiseResolver* resolver, SignalFfiError* error) {
    const char* msg = nullptr;
    SignalFfiError* msgErr = signal_error_get_message(&msg, error);
    std::string errorMsg = msg ? msg : "Unknown error";
    if (msg) signal_free_string(msg);
    if (msgErr) signal_error_free(msgErr);
    signal_error_free(error);
    resolver->reject(errorMsg);
}

// Helper: resolve with a boolean value
static void promise_complete_bool(SignalFfiError* error, const bool* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else {
        resolver->resolve_bool(result ? *result : false);
    }
    delete resolver;
}

// Helper: resolve with an i32 value
static void promise_complete_i32(SignalFfiError* error, const int32_t* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else {
        resolver->resolve_int(result ? *result : 0);
    }
    delete resolver;
}

// Helper: resolve with an OwnedBuffer (Uint8Array)
static void promise_complete_buffer(SignalFfiError* error, const SignalOwnedBuffer* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else if (result && result->base) {
        auto data = std::make_shared<std::vector<uint8_t>>(result->base, result->base + result->length);
        resolver->resolve_with_data(std::move(data));
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

// Helper: resolve with a ServiceId buffer
static void promise_complete_service_id_buffer(
        SignalFfiError* error,
        const SignalOwnedBufferOfServiceIdFixedWidthBinaryBytes* result,
        const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else if (result && result->base && result->length > 0) {
        size_t totalBytes = result->length * sizeof(SignalServiceIdFixedWidthBinaryBytes);
        auto data = std::make_shared<std::vector<uint8_t>>(
            reinterpret_cast<const uint8_t*>(result->base),
            reinterpret_cast<const uint8_t*>(result->base) + totalBytes);
        resolver->resolve_with_data(std::move(data));
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

// Helper: resolve with an optional UUID
static void promise_complete_optional_uuid(SignalFfiError* error, const SignalOptionalUuid* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else if (result && result->present) {
        auto data = std::make_shared<std::vector<uint8_t>>(
            result->bytes, result->bytes + 16);
        resolver->resolve_with_data(std::move(data));
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

// Helper: resolve with an optional pair (string, u32)
static void promise_complete_optional_pair(SignalFfiError* error, const SignalOptionalPairOfc_charu832* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

// Template: resolve with a NativePointer wrapping a pointer result
template<typename T>
static void promise_complete_pointer(SignalFfiError* error, const T* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else if (result) {
        void* ptrVal = reinterpret_cast<void*>(
            const_cast<typename std::remove_const<decltype(result->raw)>::type>(result->raw));
        resolver->resolve_with_pointer(ptrVal);
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

// Template: resolve with a NativePointer wrapping an opaque struct result (no .raw member)
template<typename T>
static void promise_complete_opaque(SignalFfiError* error, const T* result, const void* context) {
    auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(context));
    if (error) {
        promise_reject_error(resolver, error);
    } else if (result) {
        // Copy the struct and wrap it as a NativePointer
        T* copy = new T(*result);
        resolver->resolve_with_pointer(reinterpret_cast<void*>(copy));
    } else {
        resolver->resolve_null();
    }
    delete resolver;
}

} // namespace libsignal

"""


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <signal_ffi.h> <output.cpp> [Native.ts]")
        sys.exit(1)

    header_path = sys.argv[1]
    output_path = sys.argv[2]
    native_ts_path = sys.argv[3] if len(sys.argv) > 3 else None

    if not os.path.exists(header_path):
        print(f"Error: {header_path} not found")
        sys.exit(1)

    generate_bindings(header_path, native_ts_path, output_path)


if __name__ == '__main__':
    main()
