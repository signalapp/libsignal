use libc::{c_char, c_uchar, c_uint, c_ulonglong, size_t};
use libsignal_protocol_rust::*;
use num_derive::ToPrimitive;
use std::ffi::{CStr, CString};
use std::fmt;

#[derive(Debug)]
pub enum SignalFfiError {
    Signal(SignalProtocolError),
    InsufficientOutputSize(usize, usize),
    NullPointer,
    InvalidUtf8String,
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    CallbackError(i32),
    InvalidType,
}

#[derive(Debug, ToPrimitive)]
#[repr(C)]
pub enum SignalErrorCode {
    UnknownError = 1,
    InvalidState = 2,
    InternalError = 3,
    NullParameter = 4,
    InvalidArgument = 5,
    InvalidType = 6,
    InvalidUtf8String = 7,
    InsufficientOutputSize = 8,

    ProtobufError = 10,

    InvalidCiphertext = 20,
    LegacyCiphertextVersion = 21,
    UnknownCiphertextVersion = 22,
    UnrecognizedMessageVersion = 23,
    InvalidMessage = 30,

    InvalidKey = 40,
    InvalidSignature = 41,

    FingerprintIdentifierMismatch = 50,
    FingerprintVersionMismatch = 51,

    UntrustedIdentity = 60,

    InvalidKeyIdentifier = 70,

    SessionNotFound = 80,

    DuplicatedMessage = 90,

    CallbackError = 100,
}

impl SignalFfiError {
    pub fn signal_error_code(&self) -> SignalErrorCode {
        match self {
            SignalFfiError::NullPointer => SignalErrorCode::NullParameter,
            SignalFfiError::InvalidType => SignalErrorCode::InvalidType,
            SignalFfiError::UnexpectedPanic(_) => SignalErrorCode::InternalError,

            SignalFfiError::CallbackError(_) => SignalErrorCode::CallbackError,
            SignalFfiError::InvalidUtf8String => SignalErrorCode::InvalidUtf8String,
            SignalFfiError::InsufficientOutputSize(_, _) => SignalErrorCode::InsufficientOutputSize,

            SignalFfiError::Signal(SignalProtocolError::ProtobufEncodingError(_))
            | SignalFfiError::Signal(SignalProtocolError::ProtobufDecodingError(_)) => {
                SignalErrorCode::ProtobufError
            }

            SignalFfiError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
                SignalErrorCode::DuplicatedMessage
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSignedPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSenderKeyId) => {
                SignalErrorCode::InvalidKeyIdentifier
            }

            SignalFfiError::Signal(SignalProtocolError::SignatureValidationFailed) => {
                SignalErrorCode::InvalidSignature
            }

            SignalFfiError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
            | SignalFfiError::Signal(SignalProtocolError::BadKeyType(_))
            | SignalFfiError::Signal(SignalProtocolError::BadKeyLength(_, _)) => {
                SignalErrorCode::InvalidKey
            }

            SignalFfiError::Signal(SignalProtocolError::SessionNotFound) => {
                SignalErrorCode::SessionNotFound
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintIdentifierMismatch) => {
                SignalErrorCode::FingerprintIdentifierMismatch
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintVersionMismatch) => {
                SignalErrorCode::FingerprintVersionMismatch
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidMessage(_))
            | SignalFfiError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
            | SignalFfiError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_))
            | SignalFfiError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidCiphertext)
            | SignalFfiError::Signal(SignalProtocolError::InvalidProtobufEncoding) => {
                SignalErrorCode::InvalidMessage
            }

            SignalFfiError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
                SignalErrorCode::LegacyCiphertextVersion
            }

            SignalFfiError::Signal(SignalProtocolError::UntrustedIdentity(_)) => {
                SignalErrorCode::UntrustedIdentity
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidState(_, _))
            | SignalFfiError::Signal(SignalProtocolError::NoSenderKeyState)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSessionStructure) => {
                SignalErrorCode::InvalidState
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidArgument(_)) => {
                SignalErrorCode::InvalidArgument
            }

            _ => SignalErrorCode::UnknownError,
        }
    }
}

impl fmt::Display for SignalFfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalFfiError::Signal(s) => write!(f, "{}", s),
            SignalFfiError::CallbackError(c) => {
                write!(f, "callback invocation returned error code {}", c)
            }
            SignalFfiError::NullPointer => write!(f, "null pointer"),
            SignalFfiError::InvalidType => write!(f, "invalid type"),
            SignalFfiError::InvalidUtf8String => write!(f, "invalid UTF8 string"),
            SignalFfiError::InsufficientOutputSize(n, h) => {
                write!(f, "needed {} elements only {} provided", n, h)
            }

            SignalFfiError::UnexpectedPanic(e) => match e.downcast_ref::<&'static str>() {
                Some(s) => write!(f, "unexpected panic: {}", s),
                None => write!(f, "unknown unexpected panic"),
            },
        }
    }
}

impl From<SignalProtocolError> for SignalFfiError {
    fn from(e: SignalProtocolError) -> SignalFfiError {
        SignalFfiError::Signal(e)
    }
}

pub fn run_ffi_safe<F: FnOnce() -> Result<(), SignalFfiError> + std::panic::UnwindSafe>(
    f: F,
) -> *mut SignalFfiError {
    let result = match std::panic::catch_unwind(f) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(r) => Err(SignalFfiError::UnexpectedPanic(r)),
    };

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => Box::into_raw(Box::new(e)),
    }
}

pub unsafe fn box_object<T>(
    p: *mut *mut T,
    obj: Result<T, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if p.is_null() {
        return Err(SignalFfiError::NullPointer);
    }
    match obj {
        Ok(o) => {
            *p = Box::into_raw(Box::new(o));
            Ok(())
        }
        Err(e) => {
            *p = std::ptr::null_mut();
            Err(SignalFfiError::Signal(e))
        }
    }
}

pub unsafe fn box_optional_object<T>(
    p: *mut *mut T,
    obj: Result<Option<T>, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if p.is_null() {
        return Err(SignalFfiError::NullPointer);
    }
    match obj {
        Ok(Some(o)) => {
            *p = Box::into_raw(Box::new(o));
            Ok(())
        }
        Ok(None) => {
            *p = std::ptr::null_mut();
            Ok(())
        }
        Err(e) => {
            *p = std::ptr::null_mut();
            Err(SignalFfiError::Signal(e))
        }
    }
}

pub unsafe fn as_slice<'a>(
    input: *const c_uchar,
    input_len: size_t,
) -> Result<&'a [u8], SignalFfiError> {
    if input.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(std::slice::from_raw_parts(input, input_len as usize))
}

pub unsafe fn as_slice_mut<'a>(
    input: *mut c_uchar,
    input_len: size_t,
) -> Result<&'a mut [u8], SignalFfiError> {
    if input.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(std::slice::from_raw_parts_mut(input, input_len as usize))
}

/*
pub unsafe fn native_handle_cast_mut<T>(handle: *mut T) -> Result<&'static mut T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&mut *(handle))
}
*/
pub unsafe fn native_handle_cast_optional<T>(
    handle: *const T,
) -> Result<Option<&'static T>, SignalFfiError> {
    if handle.is_null() {
        return Ok(None);
    }

    Ok(Some(&*(handle)))
}

pub unsafe fn native_handle_cast<T>(handle: *const T) -> Result<&'static T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&*(handle))
}

pub unsafe fn read_c_string(cstr: *const c_char) -> Result<String, SignalFfiError> {
    if cstr.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match CStr::from_ptr(cstr).to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => Err(SignalFfiError::InvalidUtf8String),
    }
}

pub fn write_cstr_to(
    out: *mut c_uchar,
    out_len: *mut size_t,
    value: Result<String, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() || out_len.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    //let value = value.map_err(|e| SignalFfiError::Signal(e))?;

    match value {
        Ok(value) => {
            let cstr =
                CString::new(value).expect("No NULL characters in string being returned to C");
            let cstr_bytes = cstr.into_bytes_with_nul();

            unsafe {
                let space_avail = *out_len;
                *out_len = cstr_bytes.len();
                if space_avail < cstr_bytes.len() {
                    return Err(SignalFfiError::InsufficientOutputSize(
                        cstr_bytes.len(),
                        space_avail,
                    ));
                }
                std::ptr::copy_nonoverlapping(cstr_bytes.as_ptr(), out, cstr_bytes.len());
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

pub fn write_uint32_to(
    out: *mut c_uint,
    value: Result<u32, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(value) => {
            unsafe {
                *out = value;
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

pub fn write_optional_uint32_to(
    out: *mut c_uint,
    value: Result<Option<u32>, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(value) => {
            let value = value.unwrap_or(0xFFFFFFFF);
            unsafe {
                *out = value;
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

pub fn write_uint64_to(
    out: *mut c_ulonglong,
    value: Result<u64, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(value) => {
            unsafe {
                *out = value;
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

pub fn write_bytearray_to<T: AsRef<[u8]>>(
    out: *mut c_uchar,
    out_len: *mut size_t,
    value: Result<T, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() || out_len.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(value) => {
            let value: &[u8] = value.as_ref();

            unsafe {
                let space_avail = *out_len;
                *out_len = value.len();
                if space_avail < value.len() {
                    return Err(SignalFfiError::InsufficientOutputSize(
                        value.len(),
                        space_avail,
                    ));
                }

                std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

#[macro_export]
macro_rules! ffi_fn_deserialize {
    ( $nm:ident($typ:ty) is $func:path  ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            p: *mut *mut $typ,
            data: *const c_uchar,
            data_len: size_t,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                if data.is_null() {
                    return Err(SignalFfiError::NullPointer);
                }
                let data = std::slice::from_raw_parts(data, data_len);
                box_object(p, $func(data))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_new_boxed_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            new_obj: *mut *mut $rt,
            obj: *const $typ,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                box_object::<$rt>(new_obj, $body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_new_boxed_optional_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            new_obj: *mut *mut $rt,
            obj: *const $typ,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                box_optional_object::<$rt>(new_obj, $body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_uint32 {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(obj: *const $typ, out: *mut c_uint) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                write_uint32_to(out, $body(&obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_optional_uint32 {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(obj: *const $typ, out: *mut c_uint) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                write_optional_uint32_to(out, $body(&obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_uint64 {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            obj: *const $typ,
            out: *mut c_ulonglong,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                write_uint64_to(out, $body(&obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_bytearray {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            obj: *const $typ,
            out: *mut c_uchar,
            out_len: *mut size_t,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                write_bytearray_to(out, out_len, $body(&obj))
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_get_cstring {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            obj: *const $typ,
            out: *mut c_uchar,
            out_len: *mut size_t,
        ) -> *mut SignalFfiError {
            fn inner_get(t: &$typ) -> Result<String, SignalProtocolError> {
                $body(&t)
            }
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                write_cstr_to(out, out_len, inner_get(&obj))?;
                Ok(())
            })
        }
    };
}

#[macro_export]
macro_rules! ffi_fn_destroy {
    ( $nm:ident destroys $typ:ty ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(p: *mut $typ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                if !p.is_null() {
                    Box::from_raw(p);
                }
                Ok(())
            })
        }
    };
}
