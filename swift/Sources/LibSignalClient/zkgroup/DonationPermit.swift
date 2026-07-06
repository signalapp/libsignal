//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// A single use bearer token sent by the client to the donation endpoint.
public class DonationPermit: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_donation_permit_check_valid_contents)
    }
    public func verify(
        keyPair: DonationPermitDerivedKeyPair,
        now: Date = Date(),
    ) throws {
        try withUnsafeBorrowedBuffer { permit in
            try keyPair.withUnsafeBorrowedBuffer { keyPair in
                try checkError(signal_donation_permit_verify(permit, UInt64(now.timeIntervalSince1970), keyPair))
            }
        }
    }
    public lazy var spendId: Data = failOnError {
        try withUnsafeBorrowedBuffer { permit in
            try invokeFnReturningData {
                signal_donation_permit_spend_id($0, permit)
            }
        }
    }

    /// The expiration after which this permit can no longer be redeemed.
    public lazy var expiration: Date = failOnError {
        Date(
            timeIntervalSince1970: TimeInterval(
                try withUnsafeBorrowedBuffer { permit in
                    try invokeFnReturningInteger {
                        signal_donation_permit_expiration($0, permit)
                    }
                }
            )
        )
    }
}
public class DonationPermitDerivedKeyPair: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_donation_permit_derived_key_pair_check_valid_contents)
    }
    public static func forExpiration(expiration: Date, params: ServerSecretParams) -> DonationPermitDerivedKeyPair {
        failOnError {
            try params.withNativeHandle { params in
                try invokeFnReturningVariableLengthSerialized {
                    signal_donation_permit_derived_key_pair_for_expiration(
                        $0,
                        UInt64(expiration.timeIntervalSince1970),
                        params.const(),
                    )
                }
            }
        }
    }
}
/// The blinded request sent from the client to the issuing server over the authenticated channel.
public class DonationPermitRequest: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_donation_permit_request_check_valid_contents)
    }
    public func issue(
        keyPair: DonationPermitDerivedKeyPair,
        randomness: Randomness,
    ) -> DonationPermitResponse {
        failOnError {
            try withUnsafeBorrowedBuffer { request in
                try keyPair.withUnsafeBorrowedBuffer { keyPair in
                    try randomness.withUnsafePointerToBytes { randomness in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_donation_permit_response_issue_deterministic($0, request, keyPair, randomness)
                        }
                    }
                }
            }
        }
    }
}
/// Client local state used while obtaining permits.
///
/// The context contains nonces and blinding scalars. Keep it only until the
/// issuing server responds. It is needed to unblind the response. Store the
/// permits, not this context.
public class DonationPermitRequestContext: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_donation_permit_request_context_check_valid_contents)
    }
    /// Creates a client request context for `count` permits.
    public static func forCount(count: Int) throws -> DonationPermitRequestContext {
        return try self.forCount(count: count, randomness: Randomness.generate())
    }

    /// Creates a client request context for `count` permits with deterministic randomness.
    public static func forCount(
        count: Int,
        randomness: Randomness,
    ) -> DonationPermitRequestContext {
        precondition(count > 0)
        return failOnError {
            try randomness.withBorrowed { randomness in
                try invokeFnReturningVariableLengthSerialized {
                    signal_donation_permit_request_context_new_deterministic($0, Int32(count), randomness)
                }
            }
        }
    }
    /// Produces the blinded request to send to the issuing server over the authenticated channel.
    public func request() -> DonationPermitRequest {
        return failOnError {
            try withUnsafeBorrowedBuffer { context in
                try invokeFnReturningVariableLengthSerialized {
                    signal_donation_permit_request_context_request($0, context)
                }
            }
        }
    }
    /// Verifies the issuing server's response against the pinned root public key.
    /// Checks the expiration window and unblinds one permit per requested nonce.
    public func receive(
        response: DonationPermitResponse,
        publicParams: ServerPublicParams,
        now: Date = Date(),
    ) throws -> [DonationPermit] {
        let serialized = try withUnsafeBorrowedBuffer { context in
            try response.withUnsafeBorrowedBuffer { response in
                try publicParams.withNativeHandle { publicParams in
                    try invokeFnReturningBytestringArray {
                        signal_donation_permit_request_context_receive(
                            $0,
                            context,
                            response,
                            publicParams.const(),
                            UInt64(now.timeIntervalSince1970),
                        )
                    }
                }
            }
        }
        return try serialized.map { try DonationPermit(contents: $0) }
    }
}
/// The issuing server's response to a donation permit request.
public class DonationPermitResponse: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_donation_permit_response_check_valid_contents)
    }

    /// The shared expiration for the permits in this response.
    public lazy var expiration: Date = failOnError {
        Date(
            timeIntervalSince1970: TimeInterval(
                try withUnsafeBorrowedBuffer { contents in
                    try invokeFnReturningInteger {
                        signal_donation_permit_response_get_expiration($0, contents)
                    }
                }
            )
        )
    }

    public static func defaultExpiration(currentTime: Date = Date()) -> Date {
        failOnError {
            Date(
                timeIntervalSince1970: TimeInterval(
                    try invokeFnReturningInteger {
                        signal_donation_permit_response_default_expiration(
                            $0,
                            UInt64(currentTime.timeIntervalSince1970)
                        )
                    }
                )
            )
        }
    }
}
