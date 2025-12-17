//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::UnwindSafe;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use libsignal_net::chat::ChatConnection;
use libsignal_net_chat::api::Unauth;

use super::*;
// TODO: This re-export is because of the jni_arg_type macro expecting all bridging structs to be
// under the jni module; eventually we should be able to remove it.
pub use crate::net::chat::{JavaBridgeChatListener, JavaBridgeProvisioningListener};

fn attach_and_log_on_error(
    vm: &JavaVM,
    name: &'static str,
    operation: impl FnOnce(&mut JNIEnv<'_>) -> Result<(), BridgeLayerError>,
) {
    let attach_and_run = move || {
        let mut env = vm.attach_current_thread().expect("can attach thread");
        env.with_local_frame(REASONABLE_JNI_BACKGROUND_THREAD_FRAME_SIZE, |env| {
            Ok(operation(env))
        })
        .check_exceptions(&mut env, name)
        .unwrap_or_else(Err)
    };
    match attach_and_run() {
        Ok(()) => {}
        Err(e) => {
            log::error!("failed to report {name}: {e}")
        }
    }
}

pub type JavaConnectChatBridge<'a> = JObject<'a>;

const CONNECTION_MANAGER_CLASS: ClassName =
    ClassName("org.signal.libsignal.net.Network$ConnectionManager");

#[derive(Debug)]
pub struct JniConnectChatBridge {
    vm: JavaVM,
    /// Guaranteed to be a [`CONNECTION_MANAGER_CLASS`].
    connection_manager: GlobalRef,
}

#[derive(Debug)]
pub struct JniConnectChat {
    tokio_runtime: tokio::runtime::Handle,
    bridge: JniConnectChatBridge,
}

impl JniConnectChatBridge {
    pub fn new(
        env: &mut JNIEnv<'_>,
        connection_manager: &JObject,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(env, connection_manager, CONNECTION_MANAGER_CLASS)?;

        Ok(Self {
            vm: env.get_java_vm().expect("can get VM"),
            connection_manager: env.new_global_ref(connection_manager).expect("can get env"),
        })
    }
}

impl crate::net::registration::ConnectChatBridge for JniConnectChatBridge {
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn libsignal_net_chat::registration::ConnectUnauthChat + Send + Sync + UnwindSafe>
    {
        Box::new(JniConnectChat {
            tokio_runtime: runtime,
            bridge: *self,
        })
    }
}

impl libsignal_net_chat::registration::ConnectUnauthChat for JniConnectChat {
    fn connect_chat(
        &self,
        on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ChatConnectError>> {
        let Self {
            bridge:
                JniConnectChatBridge {
                    connection_manager: java_connection_manager,
                    vm,
                },
            tokio_runtime,
        } = self;

        let mut connect = None;
        attach_and_log_on_error(vm, "connect chat", |env| {
            let handle = call_method_checked(
                env,
                java_connection_manager,
                "getConnectionManagerUnsafeNativeHandle",
                jni_args!(() -> long),
            )?;
            // Safety: the returned value won't outlive the JniConnectChat
            // since it won't outlive the resolved value of the future, and the
            // future can't outlive `self`.
            let connection_manager = unsafe { BridgeHandle::native_handle_cast(handle)?.as_ref() };
            connect = Some(crate::net::chat::connect_registration_chat(
                tokio_runtime,
                connection_manager,
                on_disconnect,
            ));
            Ok(())
        });

        match connect {
            Some(connect) => connect.boxed(),
            None => {
                log::error!("failed to start chat connection attempt");
                std::future::ready(Err(ChatConnectError::InvalidConnectionConfiguration)).boxed()
            }
        }
    }
}
