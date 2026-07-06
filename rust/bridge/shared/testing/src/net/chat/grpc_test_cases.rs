//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! This module doesn't use nice derive for bridging because nice derive (does not currently)
//! support generics in client languages.

use libsignal_net_chat::grpc::GrpcTestCase;

use crate::*;

#[cfg(feature = "ffi")]
mod grpc_ffi_testing {
    #[cfg(feature = "metadata")]
    use libsignal_bridge_types::ffi::NiceResultConverter;
    use libsignal_bridge_types::ffi::{OwnedBufferOf, ResultTypeInfo, SignalFfiResult};

    use super::*;

    #[repr(C)]
    pub struct FfiErasedForTesting {
        // The argument should be the pointer to the contents directly.
        // This will be a _shallow_ destroy, because the Box<T> should already be over an FFI-ed
        // type, so it shouldn't have a destructor.
        destroy: unsafe extern "C" fn(*mut std::ffi::c_void),
        contents: *mut std::ffi::c_void,
    }
    impl<T> From<Box<T>> for FfiErasedForTesting {
        fn from(value: Box<T>) -> Self {
            let contents = Box::into_raw(value) as *mut _;
            Self {
                destroy: destroy_erased::<T>,
                contents,
            }
        }
    }
    unsafe extern "C" fn destroy_erased<T>(contents: *mut std::ffi::c_void) {
        unsafe {
            let contents = contents as *mut T;
            let b: Box<T> = Box::from_raw(contents);
            std::mem::drop(b);
        }
    }
    #[repr(C)]
    pub struct GrpcTestCaseBridgedFfi {
        name: *const std::ffi::c_char,
        method: *const std::ffi::c_char,
        request: FfiErasedForTesting,
        request_grpc: OwnedBufferOf<std::ffi::c_uchar>,
        response_grpc: OwnedBufferOf<std::ffi::c_uchar>,
        response: FfiErasedForTesting,
    }

    /// Just free the outer buffer
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn signal_free_testing_signle_grpc_testing_bridged_vec(
        buffer: OwnedBufferOf<GrpcTestCaseBridgedFfi>,
    ) {
        std::mem::drop(unsafe { buffer.into_box() });
    }

    impl<Req: ResultTypeInfo, Resp: ResultTypeInfo> ResultTypeInfo for GrpcTestCases<Req, Resp> {
        type ResultType = OwnedBufferOf<GrpcTestCaseBridgedFfi>;

        fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
            Ok(self
                .0
                .into_iter()
                .map(
                    |GrpcTestCaseBridged {
                         name,
                         method,
                         request,
                         request_grpc,
                         response_grpc,
                         response,
                     }| {
                        Ok(GrpcTestCaseBridgedFfi {
                            name: name.convert_into()?,
                            method: method.convert_into()?,
                            request: Box::new(request.convert_into()?).into(),
                            request_grpc: request_grpc.convert_into()?,
                            response_grpc: response_grpc.convert_into()?,
                            response: Box::new(response.convert_into()?).into(),
                        })
                    },
                )
                .collect::<SignalFfiResult<Vec<_>>>()?
                .into_boxed_slice()
                .into())
        }
    }
    #[cfg(feature = "metadata")]
    impl<Req: NiceResultConverter, Resp: NiceResultConverter> NiceResultConverter
        for GrpcTestCases<Req, Resp>
    {
        fn register_swift_result_converter(
            ctx: &mut libsignal_bridge_types::ffi::SwiftMetadataContext,
        ) -> libsignal_bridge_types::ffi::SwiftReturnConverter {
            let req = Req::register_swift_result_converter(ctx);
            let resp = Resp::register_swift_result_converter(ctx);
            libsignal_bridge_types::ffi::SwiftReturnConverter {
                nice_type: format!("[GrpcTestCase<{}, {}>]", req.nice_type, resp.nice_type),
                converter_type: format!(
                    "GrpcTestCaseVecConverter<{}, {}>",
                    req.converter_type, resp.converter_type
                ),
            }
        }
    }
}

#[cfg(feature = "ffi")]
pub(super) use grpc_ffi_testing::*;
pub struct GrpcTestCaseBridged<Req, Resp> {
    name: String,
    method: String,
    request: Req,
    request_grpc: Vec<u8>,
    response_grpc: Vec<u8>,
    response: Resp,
}
pub struct GrpcTestCases<Req, Resp>(Vec<GrpcTestCaseBridged<Req, Resp>>);

impl<
    RequestInto: Into<Request>,
    Request,
    RequestGrpc: prost::Message,
    ResponseGrpc: prost::Message,
    ResponseInto: Into<Response>,
    Response,
> From<Vec<GrpcTestCase<RequestInto, RequestGrpc, ResponseGrpc, ResponseInto>>>
    for GrpcTestCases<Request, Response>
{
    fn from(
        value: Vec<GrpcTestCase<RequestInto, RequestGrpc, ResponseGrpc, ResponseInto>>,
    ) -> Self {
        Self(
            value
                .into_iter()
                .map(
                    |GrpcTestCase {
                         name,
                         method,
                         request,
                         request_grpc,
                         response_grpc,
                         response,
                     }| {
                        let mut response_grpc = response_grpc.encode_to_vec();
                        let len = u32::try_from(response_grpc.len()).expect("u32 conversion");
                        let header =
                            super::TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength(len);
                        response_grpc.splice(0..0, header);
                        GrpcTestCaseBridged {
                            name,
                            method,
                            request: request.into(),
                            response: response.into(),
                            request_grpc: request_grpc.encode_to_vec(),
                            response_grpc,
                        }
                    },
                )
                .collect(),
        )
    }
}

#[cfg(feature = "node")]
impl<'a, Req: node::ResultTypeInfo<'a>, Resp: node::ResultTypeInfo<'a>> node::ResultTypeInfo<'a>
    for GrpcTestCases<Req, Resp>
{
    type ResultType = neon::prelude::JsArray;

    fn convert_into(self, cx: &mut node::Cx<'a>) -> node::JsResult<'a, Self::ResultType> {
        use neon::prelude::*;
        let out = cx.empty_array();
        for (
            i,
            GrpcTestCaseBridged {
                name,
                method,
                request,
                request_grpc,
                response_grpc,
                response,
            },
        ) in (0..).zip(self.0)
        {
            let name = cx.string(name);
            let method = cx.string(method);
            let request = request.convert_into(cx)?;
            let request_grpc = request_grpc.convert_into(cx)?;
            let response_grpc = response_grpc.convert_into(cx)?;
            let response = response.convert_into(cx)?;
            let obj = cx.empty_object();
            obj.prop(cx, "name").set(name)?;
            obj.prop(cx, "method").set(method)?;
            obj.prop(cx, "request").set(request)?;
            obj.prop(cx, "requestGrpc").set(request_grpc)?;
            obj.prop(cx, "responseGrpc").set(response_grpc)?;
            obj.prop(cx, "response").set(response)?;
            out.prop(cx, i).set(obj)?;
        }
        Ok(out)
    }

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(ctx: &mut node::TsMetadataContext) -> String {
        let req = Req::register_ts_ffi_type(ctx);
        let resp = Resp::register_ts_ffi_type(ctx);
        format!("Array<GrpcTestCaseFfi<{req}, {resp}>>")
    }
}
#[cfg(all(feature = "node", feature = "metadata"))]
impl<
    'a,
    Req: node::NiceResultConverter + node::ResultTypeInfo<'a>,
    Resp: node::NiceResultConverter + node::ResultTypeInfo<'a>,
> node::NiceResultConverter for GrpcTestCases<Req, Resp>
{
    fn register_ts_result_converter(ctx: &mut node::TsMetadataContext) -> node::TsReturnConverter {
        let req = Req::register_ts_result_converter(ctx);
        let resp = Resp::register_ts_result_converter(ctx);
        node::TsReturnConverter {
            nice_type: format!("Array<GrpcTestCase<{}, {}>>", req.nice_type, resp.nice_type),
            ffi_type: <Self as node::ResultTypeInfo<'a>>::register_ts_ffi_type(ctx),
            converter_function: format!(
                "grpcTestCaseConverter({}, {})",
                req.converter_function, resp.converter_function
            ),
        }
    }
}

#[cfg(feature = "jni")]
impl<'a, Req: jni::ResultTypeInfo<'a>, Resp: jni::ResultTypeInfo<'a>> jni::ResultTypeInfo<'a>
    for GrpcTestCases<Req, Resp>
{
    type ResultType = ::jni::objects::JObjectArray<'a>;

    fn convert_into(
        self,
        env: &mut ::jni::Env<'a>,
    ) -> Result<Self::ResultType, jni::BridgeLayerError> {
        use ::jni::refs::Reference;
        use libsignal_bridge_types::jni::HandleJniError;
        let object_class =
            ::jni::objects::JObject::lookup_class(env, &jni::loader_context().unwrap_or_default())
                .check_exceptions(env, "lookup java.lang.Object")?;
        jni::make_object_array_mapped(
            env,
            &object_class,
            self.0,
            |env,
             GrpcTestCaseBridged {
                 name,
                 method,
                 request,
                 request_grpc,
                 response_grpc,
                 response,
             }| {
                let name = name.convert_into(env)?;
                let method = method.convert_into(env)?;
                let request = request.convert_into(env)?;
                let request_grpc = request_grpc.convert_into(env)?;
                let response_grpc = response_grpc.convert_into(env)?;
                let response = response.convert_into(env)?;
                let request = jni::box_primitive_if_needed(env, request.into())?;
                let response = jni::box_primitive_if_needed(env, response.into())?;
                jni::new_instance(
                    env,
                    jni::ClassName("org.signal.libsignal.net.GrpcTestCase"),
                    libsignal_bridge_types::jni_args!((
                        name => java.lang.String,
                        method => java.lang.String,
                        request => java.lang.Object,
                        request_grpc => [jbyte],
                        response_grpc => [jbyte],
                        response => java.lang.Object,
                    ) -> void),
                )
            },
        )
    }
}
#[cfg(all(feature = "jni", feature = "metadata"))]
impl<Req: jni::NiceResultConverter, Resp: jni::NiceResultConverter> jni::NiceResultConverter
    for GrpcTestCases<Req, Resp>
{
    fn register_kt_result_converter(ctx: &mut jni::KtMetadataContext) -> jni::KtReturnConverter {
        let req = Req::register_kt_result_converter(ctx);
        let resp = Resp::register_kt_result_converter(ctx);
        jni::KtReturnConverter {
            nice_type: format!(
                "List<org.signal.libsignal.net.GrpcTestCase<{}, {}>>",
                req.nice_type, resp.nice_type
            ),
            ffi_type: "Array<Any?>".to_string(),
            converter_function: format!(
                "org.signal.libsignal.net.GrpcTestCase.resultConverter<{}, {}, {}, {}>({{ {}(it) }}, {{ {}(it) }})",
                req.ffi_type,
                resp.ffi_type,
                req.nice_type,
                resp.nice_type,
                req.converter_function,
                resp.converter_function,
            ),
        }
    }
}
