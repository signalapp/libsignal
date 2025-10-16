//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::UnwindSafe;

use bytes::Bytes;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use libsignal_net::chat::ChatConnection;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net_chat::api::Unauth;

use super::*;
use crate::net::chat::{ChatListener, ServerMessageAck};

pub type JavaBridgeChatListener<'a> = JObject<'a>;

pub struct JniBridgeChatListener(JniChatListener);

impl JniBridgeChatListener {
    pub fn new(env: &mut JNIEnv<'_>, listener: &JObject) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            listener,
            ClassName("org.signal.libsignal.net.internal.BridgeChatListener"),
        )?;
        Ok(Self(JniChatListener {
            vm: env.get_java_vm().expect("can get VM"),
            listener: env.new_global_ref(listener).expect("can get env"),
        }))
    }

    pub(crate) fn into_listener(self) -> Box<dyn ChatListener> {
        let Self(listener) = self;
        Box::new(listener)
    }
}

struct JniChatListener {
    vm: JavaVM,
    listener: GlobalRef,
}

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

impl ChatListener for JniChatListener {
    fn received_incoming_message(
        &mut self,
        envelope: Bytes,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    ) {
        let listener = &self.listener;
        attach_and_log_on_error(&self.vm, "incoming message", move |env| {
            let env_array = envelope.convert_into(env)?;
            let ack_handle = ack.convert_into(env)?;
            call_method_checked(
                env,
                listener,
                "onIncomingMessage",
                jni_args!((
                    env_array => [byte],
                    timestamp.epoch_millis() as i64 => long,
                    ack_handle => long,
                ) -> void),
            )
        });
    }

    fn received_queue_empty(&mut self) {
        let listener = &self.listener;
        attach_and_log_on_error(&self.vm, "queue empty", move |env| {
            call_method_checked(env, listener, "onQueueEmpty", jni_args!(() -> void))
        });
    }

    fn received_alerts(&mut self, alerts: Vec<String>) {
        let listener = &self.listener;
        attach_and_log_on_error(&self.vm, "received alerts", move |env| {
            let alerts = alerts.into_boxed_slice().convert_into(env)?;
            call_method_checked(
                env,
                listener,
                "onReceivedAlerts",
                jni_args!((alerts => [java.lang.String]) -> void),
            )
        });
    }

    fn connection_interrupted(&mut self, disconnect_cause: DisconnectCause) {
        let listener = &self.listener;
        attach_and_log_on_error(&self.vm, "connection interrupted", move |env| {
            let report_to_java = move |env, listener, throwable: JThrowable<'_>| {
                call_method_checked(
                    env,
                    listener,
                    "onConnectionInterrupted",
                    jni_args!((throwable => java.lang.Throwable) -> void),
                )?;
                Ok(())
            };
            match disconnect_cause {
                DisconnectCause::LocalDisconnect => {
                    report_to_java(env, listener, JObject::null().into())?
                }
                DisconnectCause::Error(disconnect_cause) => {
                    let throwable = SignalJniError::from(disconnect_cause).to_throwable(env);
                    throwable
                        .and_then(|throwable| report_to_java(env, listener, throwable))
                        .unwrap_or_else(|error| {
                            log::error!(
                                "failed to call onConnectionInterrupted with cause: {error}"
                            );
                        });
                }
            };
            Ok(())
        });
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
