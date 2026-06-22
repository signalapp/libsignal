//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

// swiftlint:disable superfluous_disable_command
// swiftlint and swift-format disagree on some comma formatting
// swiftlint:disable comma
// swiftlint:disable large_tuple
// Some of our type names grow long
// swiftlint:disable type_name

import Foundation
import SignalFfi

internal enum NativeNice {
    internal static func AuthenticatedChatConnection_set_device_name(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        deviceId device_id: Int32,
        encryptedName encrypted_name: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityConverter<Int32>.convertArgBorrowed(device_id) { device_idFfi in
                            DataConverter.convertArgBorrowed(encrypted_name) { encrypted_nameFfi in
                                SignalFfi.signal_authenticated_chat_connection_set_device_name(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    device_idFfi,
                                    encrypted_nameFfi,
                                )
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_account_exists(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        account: ServiceId,
    ) async throws -> Bool {
        let rawOutput: IdentityConverter<Bool>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdConverter.convertArgBorrowed(account) { accountFfi in
                            SignalFfi.signal_unauthenticated_chat_connection_account_exists(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                accountFfi,
                            )
                        }
                    }
            }
        return try IdentityConverter<Bool>.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_delete_all(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_delete_all(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_get_cdn_credentials(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        cdn: Int32,
        rng: Int64,
    ) async throws -> BackupCdnCredentials {
        let rawOutput: BackupCdnCredentialsConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityConverter<Int32>.convertArgBorrowed(cdn) { cdnFfi in
                                        IdentityConverter.convertArgBorrowed(rng) { rngFfi in
                                            SignalFfi.signal_unauthenticated_chat_connection_backup_get_cdn_credentials(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                credentialFfi,
                                                server_keysFfi,
                                                signing_keyFfi,
                                                cdnFfi,
                                                rngFfi,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try BackupCdnCredentialsConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_get_svrb_credentials(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws -> (String, String) {
        let rawOutput: PairOfStringConverterAndStringConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_get_svrb_credentials(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try PairOfStringConverterAndStringConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_refresh(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_refresh(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_set_public_key(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_set_public_key(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
}
