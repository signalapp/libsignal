//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthKeysServiceTests: UnauthChatServiceTestBase<any UnauthKeysService> {
    override class var selector: SelectorCheck { .keys }

    static let ACI = Aci(fromUUID: UUID(uuidString: "9d0652a3-dcc3-4d11-975f-74d61598733f")!)
    static let PNI = Pni(fromUUID: UUID(uuidString: "000002a3-dcc3-4d11-975f-74d61598733f")!)
    static let DEVICE_ID = DeviceId(validating: 2)!
    static let REGISTRATION_ID = 1234
    static let PRE_KEY_ID = UInt32(5)
    static let SIGNED_PRE_KEY_ID = UInt32(7)
    static let KYBER_PRE_KEY_ID = UInt32(9)
    static let SECOND_DEVICE_ID = DeviceId(validating: 3)!
    static let SECOND_REGISTRATION_ID = 5678
    static let SECOND_PRE_KEY_ID = UInt32(11)
    static let SECOND_SIGNED_PRE_KEY_ID = UInt32(13)
    static let SECOND_KYBER_PRE_KEY_ID = UInt32(15)
    // [0x11; 16]
    static let TEST_ACCESS_KEY = Data(base64Encoded: "EREREREREREREREREREREQ==")!
    static let IDENTITY_KEY = dummyIdentityKey(0x12)

    static let SIGNED_PRE_KEY_PUBLIC = dummyEcPublicKey(0x34)
    static let SIGNED_PRE_KEY_SIGNATURE = repeatedBytes(0x56, count: 64)
    static let KYBER_PRE_KEY_PUBLIC = dummyKemPublicKey(0x78)
    static let KYBER_PRE_KEY_SIGNATURE = repeatedBytes(0x9A, count: 64)
    static let PRE_KEY_PUBLIC = dummyEcPublicKey(0x43)

    static let SECOND_PRE_KEY_PUBLIC = dummyEcPublicKey(0xD4)
    static let SECOND_SIGNED_PRE_KEY_PUBLIC = dummyEcPublicKey(0x21)
    static let SECOND_SIGNED_PRE_KEY_SIGNATURE = repeatedBytes(0x32, count: 64)
    static let SECOND_KYBER_PRE_KEY_PUBLIC = dummyKemPublicKey(0x64)
    static let SECOND_KYBER_PRE_KEY_SIGNATURE = repeatedBytes(0x64, count: 64)

    static let TEST_GROUP_SEND_TOKEN = try! GroupSendFullToken(
        contents: Data(base64Encoded: "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA")!
    )

    static func repeatedBytes(_ fill: UInt8, count: Int) -> Data {
        return Data(Array(repeating: fill, count: count))
    }
    static func dummyEcPublicKey(_ fill: UInt8) -> PublicKey {
        var bytes = Data()
        bytes.append(contentsOf: [0x05])
        bytes.append(repeatedBytes(fill, count: 32))
        return try! PublicKey(bytes)
    }

    static func dummyIdentityKey(_ fill: UInt8) -> IdentityKey {
        return IdentityKey(publicKey: dummyEcPublicKey(fill))
    }

    static func dummyKemPublicKey(_ fill: UInt8) -> KEMPublicKey {
        var bytes = Data()
        bytes.append(contentsOf: [0x08])
        // 1568 is kyber1024::Parameters::PUBLIC_KEY_LENGTH
        bytes.append(repeatedBytes(fill, count: 1568))
        return try! KEMPublicKey(bytes)
    }

    func testSingleKeyWithPreKey() async throws {
        for (specifierString, specifier) in [
            ("*", DeviceSpecifier.allDevices),
            (
                Self.DEVICE_ID.description,
                DeviceSpecifier.specificDevice(Self.DEVICE_ID)
            ),
        ] {
            for (authHeaders, authValue) in [
                (
                    ["unidentified-access-key": Self.TEST_ACCESS_KEY.base64EncodedString()],
                    UserBasedAuthorization.accessKey(Self.TEST_ACCESS_KEY)
                ),
                (
                    [
                        "group-send-token": Self.TEST_GROUP_SEND_TOKEN.serialize()
                            .base64EncodedString()
                    ],
                    UserBasedAuthorization.groupSend(Self.TEST_GROUP_SEND_TOKEN),
                ),
                (
                    ["unidentified-access-key": Data(count: 16).base64EncodedString()],
                    UserBasedAuthorization.unrestrictedUnauthenticatedAccess
                ),
            ] {
                let api = self.api
                async let responseFuture = api.getPreKeys(
                    for: Self.ACI,
                    device: specifier,
                    auth: authValue,
                )
                let (request, id) = try await fakeRemote.getNextIncomingRequest()
                XCTAssertEqual(request.method, "GET")
                XCTAssertEqual(
                    request.pathAndQuery,
                    "/v2/keys/\(Self.ACI.serviceIdString)/\(specifierString)"
                )
                XCTAssertEqual(request.headers, authHeaders)
                XCTAssertEqual(request.body, Data())
                try fakeRemote.sendResponse(
                    requestId: id,
                    ChatResponse(
                        status: 200,
                        headers: ["content-type": "application/json"],
                        body: Data(
                            """
                            {
                                "identityKey": "\(Self.IDENTITY_KEY.serialize().base64EncodedString())",
                                "devices": [{
                                    "deviceId": \(Self.DEVICE_ID),
                                    "registrationId": \(Self.REGISTRATION_ID),
                                    "preKey": {
                                        "keyId": \(Self.PRE_KEY_ID),
                                        "publicKey": "\(Self.PRE_KEY_PUBLIC.serialize().base64EncodedString())"
                                    },
                                    "signedPreKey": {
                                        "keyId": \(Self.SIGNED_PRE_KEY_ID),
                                        "publicKey": "\(Self.SIGNED_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                        "signature": "\(Self.SIGNED_PRE_KEY_SIGNATURE.base64EncodedString())"
                                    },
                                    "pqPreKey": {
                                        "keyId": \(Self.KYBER_PRE_KEY_ID),
                                        "publicKey": "\(Self.KYBER_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                        "signature": "\(Self.KYBER_PRE_KEY_SIGNATURE.base64EncodedString())"
                                    }
                                }]
                            }
                            """.utf8
                        )
                    )
                )
                let (rik, bundles) = try await responseFuture
                XCTAssertEqual(rik, Self.IDENTITY_KEY)
                XCTAssertEqual(bundles.count, 1)
                let bundle = bundles[0]
                XCTAssertEqual(bundle.kyberPreKeyId, Self.KYBER_PRE_KEY_ID)
                XCTAssertEqual(bundle.preKeyId!, Self.PRE_KEY_ID)
                XCTAssertEqual(bundle.preKeyPublic!, Self.PRE_KEY_PUBLIC)
                XCTAssertEqual(bundle.signedPreKeyPublic, Self.SIGNED_PRE_KEY_PUBLIC)
                XCTAssertEqual(bundle.signedPreKeySignature, Self.SIGNED_PRE_KEY_SIGNATURE)
                XCTAssertEqual(bundle.kyberPreKeyPublic, Self.KYBER_PRE_KEY_PUBLIC)
                XCTAssertEqual(bundle.kyberPreKeySignature, Self.KYBER_PRE_KEY_SIGNATURE)
            }
        }
    }

    func testSingleKeyNoPreKey() async throws {
        for (specifierString, specifier) in [
            ("*", DeviceSpecifier.allDevices),
            (
                Self.DEVICE_ID.description,
                DeviceSpecifier.specificDevice(Self.DEVICE_ID)
            ),
        ] {
            let api = self.api
            async let responseFuture = api.getPreKeys(
                for: Self.ACI,
                device: specifier,
                auth: .accessKey(Self.TEST_ACCESS_KEY),
            )
            let (request, id) = try await fakeRemote.getNextIncomingRequest()
            XCTAssertEqual(request.method, "GET")
            XCTAssertEqual(
                request.pathAndQuery,
                "/v2/keys/\(Self.ACI.serviceIdString)/\(specifierString)"
            )
            XCTAssertEqual(
                request.headers,
                ["unidentified-access-key": Self.TEST_ACCESS_KEY.base64EncodedString()]
            )
            XCTAssertEqual(request.body, Data())
            try fakeRemote.sendResponse(
                requestId: id,
                ChatResponse(
                    status: 200,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        {
                            "identityKey": "\(Self.IDENTITY_KEY.serialize().base64EncodedString())",
                            "devices": [{
                                "deviceId": \(Self.DEVICE_ID),
                                "registrationId": \(Self.REGISTRATION_ID),
                                "signedPreKey": {
                                    "keyId": \(Self.SIGNED_PRE_KEY_ID),
                                    "publicKey": "\(Self.SIGNED_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.SIGNED_PRE_KEY_SIGNATURE.base64EncodedString())"
                                },
                                "pqPreKey": {
                                    "keyId": \(Self.KYBER_PRE_KEY_ID),
                                    "publicKey": "\(Self.KYBER_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.KYBER_PRE_KEY_SIGNATURE.base64EncodedString())"
                                }
                            }]
                        }
                        """.utf8
                    )
                )
            )
            let (rik, bundles) = try await responseFuture
            XCTAssertEqual(rik, Self.IDENTITY_KEY)
            XCTAssertEqual(bundles.count, 1)
            let bundle = bundles[0]
            XCTAssertEqual(bundle.preKeyId, nil)
            XCTAssertEqual(bundle.preKeyPublic, nil)
            XCTAssertEqual(bundle.signedPreKeyPublic, Self.SIGNED_PRE_KEY_PUBLIC)
            XCTAssertEqual(bundle.signedPreKeySignature, Self.SIGNED_PRE_KEY_SIGNATURE)
            XCTAssertEqual(bundle.kyberPreKeyPublic, Self.KYBER_PRE_KEY_PUBLIC)
            XCTAssertEqual(bundle.kyberPreKeySignature, Self.KYBER_PRE_KEY_SIGNATURE)
        }
    }
    func testAllKeys() async throws {
        let api = self.api
        async let responseFuture = api.getPreKeys(
            for: Self.PNI,
            device: .allDevices,
            auth: .accessKey(Self.TEST_ACCESS_KEY),
        )
        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v2/keys/\(Self.PNI.serviceIdString)/*")
        XCTAssertEqual(
            request.headers,
            ["unidentified-access-key": Self.TEST_ACCESS_KEY.base64EncodedString()]
        )
        XCTAssertEqual(request.body, Data())
        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "identityKey": "\(Self.IDENTITY_KEY.serialize().base64EncodedString())",
                        "devices": [
                            {
                                "deviceId": \(Self.DEVICE_ID),
                                "registrationId": \(Self.REGISTRATION_ID),
                                "signedPreKey": {
                                    "keyId": \(Self.SIGNED_PRE_KEY_ID),
                                    "publicKey": "\(Self.SIGNED_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.SIGNED_PRE_KEY_SIGNATURE.base64EncodedString())"
                                },
                                "preKey": {
                                    "keyId": \(Self.PRE_KEY_ID),
                                    "publicKey": "\(Self.PRE_KEY_PUBLIC.serialize().base64EncodedString())"
                                },
                                "pqPreKey": {
                                    "keyId": \(Self.KYBER_PRE_KEY_ID),
                                    "publicKey": "\(Self.KYBER_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.KYBER_PRE_KEY_SIGNATURE.base64EncodedString())"
                                }
                            },
                            {
                                "deviceId": \(Self.SECOND_DEVICE_ID),
                                "registrationId": \(Self.SECOND_REGISTRATION_ID),
                                "signedPreKey": {
                                    "keyId": \(Self.SECOND_SIGNED_PRE_KEY_ID),
                                    "publicKey": "\(Self.SECOND_SIGNED_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.SECOND_SIGNED_PRE_KEY_SIGNATURE.base64EncodedString())"
                                },
                                "preKey": {
                                    "keyId": \(Self.SECOND_PRE_KEY_ID),
                                    "publicKey": "\(Self.SECOND_PRE_KEY_PUBLIC.serialize().base64EncodedString())"
                                },
                                "pqPreKey": {
                                    "keyId": \(Self.SECOND_KYBER_PRE_KEY_ID),
                                    "publicKey": "\(Self.SECOND_KYBER_PRE_KEY_PUBLIC.serialize().base64EncodedString())",
                                    "signature": "\(Self.SECOND_KYBER_PRE_KEY_SIGNATURE.base64EncodedString())"
                                }
                            }
                        ]
                    }
                    """.utf8
                )
            )
        )
        let (rik, bundles) = try await responseFuture
        XCTAssertEqual(rik, Self.IDENTITY_KEY)
        XCTAssertEqual(bundles.count, 2)
        var bundle = bundles[0]
        XCTAssertEqual(bundle.preKeyId, Self.PRE_KEY_ID)
        XCTAssertEqual(bundle.preKeyPublic, Self.PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.signedPreKeyId, Self.SIGNED_PRE_KEY_ID)
        XCTAssertEqual(bundle.kyberPreKeyId, Self.KYBER_PRE_KEY_ID)
        XCTAssertEqual(bundle.signedPreKeyPublic, Self.SIGNED_PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.signedPreKeySignature, Self.SIGNED_PRE_KEY_SIGNATURE)
        XCTAssertEqual(bundle.kyberPreKeyPublic, Self.KYBER_PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.kyberPreKeySignature, Self.KYBER_PRE_KEY_SIGNATURE)
        bundle = bundles[1]
        XCTAssertEqual(bundle.preKeyId, Self.SECOND_PRE_KEY_ID)
        XCTAssertEqual(bundle.preKeyPublic, Self.SECOND_PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.signedPreKeyId, Self.SECOND_SIGNED_PRE_KEY_ID)
        XCTAssertEqual(bundle.kyberPreKeyId, Self.SECOND_KYBER_PRE_KEY_ID)
        XCTAssertEqual(bundle.signedPreKeyPublic, Self.SECOND_SIGNED_PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.signedPreKeySignature, Self.SECOND_SIGNED_PRE_KEY_SIGNATURE)
        XCTAssertEqual(bundle.kyberPreKeyPublic, Self.SECOND_KYBER_PRE_KEY_PUBLIC)
        XCTAssertEqual(bundle.kyberPreKeySignature, Self.SECOND_KYBER_PRE_KEY_SIGNATURE)
    }

    func testUnauthorized() async throws {
        let api = self.api
        async let responseFuture = api.getPreKeys(
            for: Self.ACI,
            device: .allDevices,
            auth: .accessKey(Self.TEST_ACCESS_KEY),
        )
        let (_, id) = try await fakeRemote.getNextIncomingRequest()
        try fakeRemote.sendResponse(requestId: id, ChatResponse(status: 401))
        do {
            _ = try await responseFuture
            XCTFail("Failed to throw")
        } catch SignalError.requestUnauthorized(_) {}
    }

    func testNotFoundError() async throws {
        let api = self.api
        async let responseFuture = api.getPreKeys(
            for: Self.ACI,
            device: .allDevices,
            auth: .accessKey(Self.TEST_ACCESS_KEY),
        )
        let (_, id) = try await fakeRemote.getNextIncomingRequest()
        try fakeRemote.sendResponse(requestId: id, ChatResponse(status: 404))
        do {
            _ = try await responseFuture
            XCTFail("Failed to throw")
        } catch SignalError.serviceIdNotFound(_) {}
    }
}

#endif
