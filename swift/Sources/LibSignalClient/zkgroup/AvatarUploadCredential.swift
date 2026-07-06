//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Client-side state for an in-flight avatar upload credential request.
///
/// This value is not sent over the wire; it is retained by the client between issuing a
/// ``AvatarUploadCredentialRequest`` and receiving the corresponding
/// ``AvatarUploadCredentialResponse``.
public final class AvatarUploadCredentialRequestContext: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_avatar_upload_credential_request_context_check_valid_contents)
    }

    /// Creates a new request context for `aci`.
    ///
    /// - Parameter aci: The account the credential will be issued for. The issuing server must independently
    ///     authenticate this ACI.
    /// - Parameter zkCredentialKey: The account's long-term Ristretto ZK credential key pair.
    /// - Parameter rotationId: The server-chosen avatar slot rotation ID, which the client already received
    ///     when it set its ZK credential key. It is folded into the commitment; the issuing server
    ///     verifies the request against its own rotation ID, so this must match the server's value.
    public static func create(
        aci: Aci,
        zkCredentialKey: ZkCredentialKeyPair,
        rotationId: UInt64
    ) -> AvatarUploadCredentialRequestContext {
        return failOnError {
            self.create(
                aci: aci,
                zkCredentialKey: zkCredentialKey,
                rotationId: rotationId,
                randomness: try .generate()
            )
        }
    }

    /// Creates a new request context, using a dedicated source of randomness.
    ///
    /// This can be used to make tests deterministic. Prefer ``create(aci:zkCredentialKey:rotationId:)``
    /// if the source of randomness doesn't matter.
    public static func create(
        aci: Aci,
        zkCredentialKey: ZkCredentialKeyPair,
        rotationId: UInt64,
        randomness: Randomness
    ) -> AvatarUploadCredentialRequestContext {
        return failOnError {
            try withAllBorrowed(aci, zkCredentialKey, randomness) { aci, key, randomness in
                try invokeFnReturningVariableLengthSerialized {
                    signal_avatar_upload_credential_request_context_new($0, aci, key, rotationId, randomness)
                }
            }
        }
    }

    /// The request to send to the issuing server.
    public func getRequest() -> AvatarUploadCredentialRequest {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningVariableLengthSerialized {
                    signal_avatar_upload_credential_request_context_get_request($0, contents)
                }
            }
        }
    }

    /// Verifies the issuing server's response and produces a usable ``AvatarUploadCredential``.
    ///
    /// The issuing server chooses the redemption time and embeds it in `response`. The client
    /// doesn't need to predict it; this call confirms only that the credential is usable at
    /// `now`, since the verifying server applies the same window (see
    /// ``AvatarUploadCredentialPresentation/verify(now:serverParams:)``).
    ///
    /// - Parameter response: The response received from the issuing server.
    /// - Parameter now: The client's view of wall-clock time. The response's redemption time must be
    ///     day-aligned and within the redemption window relative to this.
    /// - Parameter serverParams: The public params matching the secret params the issuing server used.
    /// - Throws ``SignalError/verificationFailed(_:)`` if the response is not valid for this context.
    public func receive(
        _ response: AvatarUploadCredentialResponse,
        now: Date = Date(),
        serverParams: GenericServerPublicParams
    ) throws -> AvatarUploadCredential {
        return try withAllBorrowed(self, response, serverParams) { contents, response, params in
            try invokeFnReturningVariableLengthSerialized {
                signal_avatar_upload_credential_request_context_receive_response(
                    $0,
                    contents,
                    response,
                    UInt64(now.timeIntervalSince1970),
                    params
                )
            }
        }
    }
}

/// The request a client sends to the issuing server to obtain an avatar upload credential.
public class AvatarUploadCredentialRequest: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_avatar_upload_credential_request_check_valid_contents)
    }

    /// Issues an avatar upload credential.
    ///
    /// - Parameter aci: The account this credential is for. The server must independently authenticate the
    ///     client as this ACI.
    /// - Parameter zkCredentialKey: The account's long-term Ristretto ZK credential public key from
    ///     the server's authoritative store for this account. The request's well-formedness proof
    ///     binds the blinded commitment to this key, so passing the wrong value will fail issuance.
    /// - Parameter rotationId: The server-chosen avatar slot rotation ID, incorporated into the commitment.
    ///     The client received this value when it set its ZK credential key.
    /// - Parameter redemptionTime: Must be a round number of days since the Unix epoch.
    /// - Parameter serverParams: The params that will be used by the verifying server to verify this credential.
    /// - Throws ``SignalError/verificationFailed(_:)`` if the request is not well-formed for `aci` and
    ///     `zkCredentialKey`.
    public func issueCredential(
        aci: Aci,
        zkCredentialKey: ZkCredentialPublicKey,
        rotationId: UInt64,
        redemptionTime: Date,
        serverParams: GenericServerSecretParams
    ) throws -> AvatarUploadCredentialResponse {
        return try self.issueCredential(
            aci: aci,
            zkCredentialKey: zkCredentialKey,
            rotationId: rotationId,
            redemptionTime: redemptionTime,
            serverParams: serverParams,
            randomness: try .generate()
        )
    }

    /// Issues an avatar upload credential, using a dedicated source of randomness.
    ///
    /// This can be used to make tests deterministic. Prefer ``issueCredential(aci:zkcredentialKey:rotationId:redemptionTime:serverParams:)``
    /// if the source of randomness  doesn't matter.
    public func issueCredential(
        aci: Aci,
        zkCredentialKey: ZkCredentialPublicKey,
        rotationId: UInt64,
        redemptionTime: Date,
        serverParams: GenericServerSecretParams,
        randomness: Randomness
    ) throws -> AvatarUploadCredentialResponse {
        return try withAllBorrowed(self, aci, zkCredentialKey, serverParams, randomness) {
            contents,
            aci,
            key,
            params,
            randomness in
            try invokeFnReturningVariableLengthSerialized {
                signal_avatar_upload_credential_request_issue_deterministic(
                    $0,
                    contents,
                    aci,
                    key,
                    rotationId,
                    UInt64(redemptionTime.timeIntervalSince1970),
                    params,
                    randomness
                )
            }
        }
    }
}

/// The issuing server's response to an ``AvatarUploadCredentialRequest``.
public class AvatarUploadCredentialResponse: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_avatar_upload_credential_response_check_valid_contents)
    }
}

/// A usable avatar upload credential, held by the client after a successful issuance.
///
/// Call ``Self/present(serverParams:)`` to produce an ``AvatarUploadCredentialPresentation`` for a verifying
/// server.
public class AvatarUploadCredential: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_avatar_upload_credential_check_valid_contents)
    }

    /// Produces a presentation of this credential for a verifying server.
    public func present(serverParams: GenericServerPublicParams) -> AvatarUploadCredentialPresentation {
        return failOnError {
            self.present(serverParams: serverParams, randomness: try .generate())
        }
    }

    /// Produces a presentation of this credential, using a dedicated source of randomness.
    ///
    /// This can be used to make tests deterministic. Prefer ``present(serverParams:)``
    /// if the source of randomness doesn't matter.
    public func present(
        serverParams: GenericServerPublicParams,
        randomness: Randomness
    ) -> AvatarUploadCredentialPresentation {
        return failOnError {
            try withAllBorrowed(self, serverParams, randomness) { contents, serverParams, randomness in
                try invokeFnReturningVariableLengthSerialized {
                    signal_avatar_upload_credential_present_deterministic($0, contents, serverParams, randomness)
                }
            }
        }
    }

    /// The 32-byte commitment `Cm` (the avatar slot identifier).
    ///
    /// This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
    public var commitment: Data {
        failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningFixedLengthArray {
                    signal_avatar_upload_credential_get_cm($0, contents)
                }
            }
        }
    }

    /// The redemption time the issuing server chose for this credential.
    public var redemptionTime: Date {
        let secondsSinceEpoch = failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningInteger {
                    signal_avatar_upload_credential_get_redemption_time($0, contents)
                }
            }
        }
        return Date(timeIntervalSince1970: TimeInterval(secondsSinceEpoch))
    }
}

/// A presentation of an ``AvatarUploadCredential``, sent to a verifying server.
public class AvatarUploadCredentialPresentation: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_avatar_upload_credential_presentation_check_valid_contents)
    }

    /// Verifies the presentation against the (given) current time.
    ///
    /// - Throws: ``SignalError/verificationFailed(_:)`` if the presentation is invalid or outside its redemption
    ///   window.
    public func verify(now: Date = Date(), serverParams: GenericServerSecretParams) throws {
        try withAllBorrowed(self, serverParams) { contents, serverParams in
            try checkError(
                signal_avatar_upload_credential_presentation_verify(
                    contents,
                    UInt64(now.timeIntervalSince1970),
                    serverParams
                )
            )
        }
    }

    /// The 32-byte commitment `Cm` (the avatar slot identifier) revealed by this presentation.
    ///
    /// This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
    public var commitment: Data {
        failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningFixedLengthArray {
                    signal_avatar_upload_credential_presentation_get_cm($0, contents)
                }
            }
        }
    }

    /// The redemption time the issuing server chose for this credential.
    public var redemptionTime: Date {
        let secondsSinceEpoch = failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningInteger {
                    signal_avatar_upload_credential_presentation_get_redemption_time($0, contents)
                }
            }
        }
        return Date(timeIntervalSince1970: TimeInterval(secondsSinceEpoch))
    }
}
