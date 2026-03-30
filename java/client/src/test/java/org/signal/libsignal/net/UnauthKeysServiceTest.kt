//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.io.encoding.Base64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UnauthKeysServiceTest {
  companion object {
    private val aci = ServiceId.Aci(UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"))
    private val pni = ServiceId.Pni(UUID.fromString("000002a3-dcc3-4d11-975f-74d61598733f"))
    private val deviceId = 2
    private val registrationId = 1234
    private val preKeyId = 5
    private val signedPreKeyId = 7
    private val kyberPreKeyId = 9
    private val secondDeviceId = 3
    private val secondRegistrationId = 5678
    private val secondPreKeyId = 11
    private val secondSignedPreKeyId = 13
    private val secondKyberPreKeyId = 15

    // [0x11; 16]
    private val testAccessKey = Base64.decode("EREREREREREREREREREREQ==")
    private val identityKey = dummyIdentityKey(0x12)

    private val signedPreKeyPublic = dummyEcPublicKey(0x34)
    private val signedPreKeySignature = ByteArray(64) { 0x56 }
    private val kyberPreKeyPublic = dummyKemPublicKey(0x78)
    private val kyberPreKeySignature = ByteArray(64) { 0x9A.toByte() }
    private val preKeyPublic = dummyEcPublicKey(0x43)
    private val secondPreKeyPublic = dummyEcPublicKey(0xD4.toByte())

    private val secondSignedPreKeyPublic = dummyEcPublicKey(0x21)
    private val secondSignedPreKeySignature = ByteArray(64) { 0x32 }
    private val secondKyberPreKeyPublic = dummyKemPublicKey(0x64)
    private val secondKyberPreKeySignature = ByteArray(64) { 0x64 }

    private val testGroupSendToken =
      GroupSendFullToken(
        Base64.decode("ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA"),
      )

    private fun dummyEcPublicKey(fill: Byte): ECPublicKey = ECPublicKey(byteArrayOf(0x05) + ByteArray(32) { fill })

    private fun dummyIdentityKey(fill: Byte): IdentityKey = IdentityKey(dummyEcPublicKey(fill))

    // kyber1024::Parameters::PUBLIC_KEY_LENGTH
    // This needs to be const to avoid java initialization order issues
    private const val KYBER1024_PUBLIC_KEY_LENGTH: Int = 1568

    private fun dummyKemPublicKey(fill: Byte): KEMPublicKey =
      KEMPublicKey(
        byteArrayOf(0x08) +
          ByteArray(KYBER1024_PUBLIC_KEY_LENGTH) { fill },
      )
  }

  private fun doTestSingleKeyWithPreKey(
    specifierString: String,
    specifier: DeviceSpecifier,
    authHeaders: Map<String, String>,
    authValue: UserBasedAuthorization,
  ) {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val service = UnauthKeysService(chat)
    val responseFuture =
      service.getPreKeys(
        aci,
        specifier,
        authValue,
      )
    // If the future is done immediately, then there's some internal error.
    if (responseFuture.isDone) {
      throw AssertionError(responseFuture.get().toString())
    }
    val (request, requestId) = fakeRemote.nextIncomingRequest.get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v2/keys/${aci.rawUUID}/$specifierString", request.pathAndQuery)
    assertEquals(authHeaders, request.headers)
    assertEquals(0, request.body.size)
    val responseBody = """
           {
               "identityKey": "${Base64.encode(identityKey.serialize())}",
               "devices": [{
                   "deviceId": $deviceId,
                   "registrationId": $registrationId,
                   "preKey": {
                       "keyId": $preKeyId,
                       "publicKey": "${Base64.encode(preKeyPublic.serialize())}"
                   },
                   "signedPreKey": {
                       "keyId": $signedPreKeyId,
                       "publicKey": "${Base64.encode(signedPreKeyPublic.serialize())}",
                       "signature": "${Base64.encode(signedPreKeySignature)}"
                   },
                   "pqPreKey": {
                       "keyId": $kyberPreKeyId,
                       "publicKey": "${Base64.encode(kyberPreKeyPublic.serialize())}",
                       "signature": "${Base64.encode(kyberPreKeySignature)}"
                   }
               }]
           }
          """
    fakeRemote.sendResponse(
      requestId,
      200,
      "OK",
      arrayOf("content-type: application/json"),
      responseBody.encodeToByteArray(),
    )
    val response = responseFuture.get()
    val (rik, bundles) = assertIs<RequestResult.Success<Pair<IdentityKey, List<PreKeyBundle>>>>(response).result
    assertEquals(identityKey, rik)
    assertEquals(1, bundles.size)
    val bundle = bundles[0]
    assertEquals(bundle.kyberPreKeyId, kyberPreKeyId)
    assertEquals(bundle.preKeyId, preKeyId)
    assertEquals(bundle.preKey, preKeyPublic)
    assertEquals(bundle.signedPreKey, signedPreKeyPublic)
    assertContentEquals(bundle.signedPreKeySignature, signedPreKeySignature)
    assertEquals(bundle.kyberPreKey, kyberPreKeyPublic)
    assertContentEquals(bundle.kyberPreKeySignature, kyberPreKeySignature)
  }

  @Test
  fun testSingleKeyWithPreKey_allDevices_accessKey() =
    doTestSingleKeyWithPreKey(
      "*",
      DeviceSpecifier.AllDevices,
      mapOf("unidentified-access-key" to Base64.encode(testAccessKey)),
      UserBasedAuthorization.AccessKey(testAccessKey),
    )

  @Test
  fun testSingleKeyWithPreKey_allDevices_groupSend() =
    doTestSingleKeyWithPreKey(
      "*",
      DeviceSpecifier.AllDevices,
      mapOf(
        "group-send-token" to
          Base64.encode(testGroupSendToken.serialize()),
      ),
      UserBasedAuthorization.GroupSend(testGroupSendToken),
    )

  @Test
  fun testSingleKeyWithPreKey_allDevices_unrestricted() =
    doTestSingleKeyWithPreKey(
      "*",
      DeviceSpecifier.AllDevices,
      mapOf("unidentified-access-key" to Base64.encode(ByteArray(16))),
      UserBasedAuthorization.UnrestrictedUnauthenticatedAccess,
    )

  @Test
  fun testSingleKeyWithPreKey_specificDevice_accessKey() =
    doTestSingleKeyWithPreKey(
      deviceId.toString(),
      DeviceSpecifier.SpecificDevice(deviceId),
      mapOf("unidentified-access-key" to Base64.encode(testAccessKey)),
      UserBasedAuthorization.AccessKey(testAccessKey),
    )

  @Test
  fun testSingleKeyWithPreKey_specificDevice_groupSend() =
    doTestSingleKeyWithPreKey(
      deviceId.toString(),
      DeviceSpecifier.SpecificDevice(deviceId),
      mapOf(
        "group-send-token" to
          Base64.encode(testGroupSendToken.serialize()),
      ),
      UserBasedAuthorization.GroupSend(testGroupSendToken),
    )

  @Test
  fun testSingleKeyWithPreKey_specificDevice_unrestricted() =
    doTestSingleKeyWithPreKey(
      deviceId.toString(),
      DeviceSpecifier.SpecificDevice(deviceId),
      mapOf("unidentified-access-key" to Base64.encode(ByteArray(16))),
      UserBasedAuthorization.UnrestrictedUnauthenticatedAccess,
    )

  @Test
  fun testSingleKeyNoPreKey() {
    for ((specifierString, specifier) in listOf(
      Pair("*", DeviceSpecifier.AllDevices),
      Pair(deviceId.toString(), DeviceSpecifier.SpecificDevice(deviceId)),
    )) {
      for ((authHeaders, authValue) in listOf(
        Pair(
          mapOf("unidentified-access-key" to Base64.encode(testAccessKey)),
          UserBasedAuthorization.AccessKey(testAccessKey),
        ),
        Pair(
          mapOf("group-send-token" to Base64.encode(testGroupSendToken.serialize())),
          UserBasedAuthorization.GroupSend(testGroupSendToken),
        ),
        Pair(
          mapOf("unidentified-access-key" to Base64.encode(ByteArray(16))),
          UserBasedAuthorization.UnrestrictedUnauthenticatedAccess,
        ),
      )) {
        val tokioAsyncContext = TokioAsyncContext()
        val (chat, fakeRemote) =
          UnauthenticatedChatConnection.fakeConnect(
            tokioAsyncContext,
            NoOpListener(),
            Network.Environment.STAGING,
          )
        val service = UnauthKeysService(chat)
        val responseFuture =
          service.getPreKeys(
            aci,
            specifier,
            authValue,
          )
        // If the future is done immediately, then there's some internal error.
        if (responseFuture.isDone) {
          throw AssertionError(responseFuture.get().toString())
        }
        val (request, requestId) = fakeRemote.nextIncomingRequest.get(1, TimeUnit.SECONDS)
        assertEquals("GET", request.method)
        assertEquals("/v2/keys/${aci.rawUUID}/$specifierString", request.pathAndQuery)
        assertEquals(authHeaders, request.headers)
        assertEquals(0, request.body.size)
        val responseBody = """
           {
               "identityKey": "${Base64.encode(identityKey.serialize())}",
               "devices": [{
                   "deviceId": $deviceId,
                   "registrationId": $registrationId,
                   "signedPreKey": {
                       "keyId": $signedPreKeyId,
                       "publicKey": "${Base64.encode(signedPreKeyPublic.serialize())}",
                       "signature": "${Base64.encode(signedPreKeySignature)}"
                   },
                   "pqPreKey": {
                       "keyId": $kyberPreKeyId,
                       "publicKey": "${Base64.encode(kyberPreKeyPublic.serialize())}",
                       "signature": "${Base64.encode(kyberPreKeySignature)}"
                   }
               }]
           }
          """
        fakeRemote.sendResponse(
          requestId,
          200,
          "OK",
          arrayOf("content-type: application/json"),
          responseBody.encodeToByteArray(),
        )
        val response = responseFuture.get()
        val (rik, bundles) = assertIs<RequestResult.Success<Pair<IdentityKey, List<PreKeyBundle>>>>(response).result
        assertEquals(identityKey, rik)
        assertEquals(1, bundles.size)
        val bundle = bundles[0]
        assertEquals(bundle.kyberPreKeyId, kyberPreKeyId)
        assertEquals(bundle.preKeyId, -1)
        assertEquals(bundle.preKey, null)
        assertEquals(bundle.signedPreKey, signedPreKeyPublic)
        assertContentEquals(bundle.signedPreKeySignature, signedPreKeySignature)
        assertEquals(bundle.kyberPreKey, kyberPreKeyPublic)
        assertContentEquals(bundle.kyberPreKeySignature, kyberPreKeySignature)
      }
    }
  }

  @Test
  fun testAllKeys() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val service = UnauthKeysService(chat)
    val responseFuture =
      service.getPreKeys(
        pni,
        DeviceSpecifier.AllDevices,
        UserBasedAuthorization.AccessKey(testAccessKey),
      )
    // If the future is done immediately, then there's some internal error.
    if (responseFuture.isDone) {
      throw AssertionError(responseFuture.get().toString())
    }
    val (request, requestId) = fakeRemote.nextIncomingRequest.get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v2/keys/${pni.toServiceIdString()}/*", request.pathAndQuery)
    assertEquals(
      mapOf(
        "unidentified-access-key" to Base64.encode(testAccessKey),
      ),
      request.headers,
    )
    assertEquals(0, request.body.size)
    val responseBody = """
          {
              "identityKey": "${Base64.encode(identityKey.serialize())}",
              "devices": [
                  {
                      "deviceId": $deviceId,
                      "registrationId": $registrationId,
                      "signedPreKey": {
                          "keyId": $signedPreKeyId,
                          "publicKey": "${Base64.encode(signedPreKeyPublic.serialize())}",
                          "signature": "${Base64.encode(signedPreKeySignature)}"
                      },
                      "preKey": {
                          "keyId": $preKeyId,
                          "publicKey": "${Base64.encode(preKeyPublic.serialize())}"
                      },
                      "pqPreKey": {
                          "keyId": $kyberPreKeyId,
                          "publicKey": "${Base64.encode(kyberPreKeyPublic.serialize())}",
                          "signature": "${Base64.encode(kyberPreKeySignature)}"
                      }
                  },
                  {
                      "deviceId": $secondDeviceId,
                      "registrationId": $secondRegistrationId,
                      "signedPreKey": {
                          "keyId": $secondSignedPreKeyId,
                          "publicKey": "${Base64.encode(secondSignedPreKeyPublic.serialize())}",
                          "signature": "${Base64.encode(secondSignedPreKeySignature)}"
                      },
                      "preKey": {
                          "keyId": $secondPreKeyId,
                          "publicKey": "${Base64.encode(secondPreKeyPublic.serialize())}"
                      },
                      "pqPreKey": {
                          "keyId": $secondKyberPreKeyId,
                          "publicKey": "${Base64.encode(secondKyberPreKeyPublic.serialize())}",
                          "signature": "${Base64.encode(secondKyberPreKeySignature)}"
                      }
                  }
              ]
          }
          """
    fakeRemote.sendResponse(
      requestId,
      200,
      "OK",
      arrayOf("content-type: application/json"),
      responseBody.encodeToByteArray(),
    )
    val response = responseFuture.get()
    val (rik, bundles) = assertIs<RequestResult.Success<Pair<IdentityKey, List<PreKeyBundle>>>>(response).result
    assertEquals(identityKey, rik)
    assertEquals(2, bundles.size)
    assertEquals(bundles[0].kyberPreKeyId, kyberPreKeyId)
    assertEquals(bundles[0].preKeyId, preKeyId)
    assertEquals(bundles[0].preKey, preKeyPublic)
    assertEquals(bundles[0].signedPreKey, signedPreKeyPublic)
    assertContentEquals(bundles[0].signedPreKeySignature, signedPreKeySignature)
    assertEquals(bundles[0].kyberPreKey, kyberPreKeyPublic)
    assertContentEquals(bundles[0].kyberPreKeySignature, kyberPreKeySignature)
    assertEquals(bundles[1].kyberPreKeyId, secondKyberPreKeyId)
    assertEquals(bundles[1].preKeyId, secondPreKeyId)
    assertEquals(bundles[1].preKey, secondPreKeyPublic)
    assertEquals(bundles[1].signedPreKey, secondSignedPreKeyPublic)
    assertContentEquals(bundles[1].signedPreKeySignature, secondSignedPreKeySignature)
    assertEquals(bundles[1].kyberPreKey, secondKyberPreKeyPublic)
    assertContentEquals(bundles[1].kyberPreKeySignature, secondKyberPreKeySignature)
  }

  @Test
  fun testUnauthorized() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val service = UnauthKeysService(chat)
    val responseFuture =
      service.getPreKeys(
        aci,
        DeviceSpecifier.AllDevices,
        UserBasedAuthorization.AccessKey(testAccessKey),
      )
    val (request, requestId) = fakeRemote.nextIncomingRequest.get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v2/keys/${aci.rawUUID}/*", request.pathAndQuery)
    assertEquals(
      mapOf(
        "unidentified-access-key" to Base64.encode(testAccessKey),
      ),
      request.headers,
    )
    assertEquals(0, request.body.size)
    fakeRemote.sendResponse(requestId, 401, "Unauthorized", arrayOf(), byteArrayOf())
    val error = assertIs<RequestResult.NonSuccess<GetPreKeysError>>(responseFuture.get()).error
    assertIs<RequestUnauthorizedException>(error)
  }

  @Test
  fun testNotFound() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val service = UnauthKeysService(chat)
    val responseFuture =
      service.getPreKeys(
        aci,
        DeviceSpecifier.AllDevices,
        UserBasedAuthorization.AccessKey(testAccessKey),
      )
    val (request, requestId) = fakeRemote.nextIncomingRequest.get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v2/keys/${aci.rawUUID}/*", request.pathAndQuery)
    assertEquals(
      mapOf(
        "unidentified-access-key" to Base64.encode(testAccessKey),
      ),
      request.headers,
    )
    assertEquals(0, request.body.size)
    fakeRemote.sendResponse(requestId, 404, "Not Found", arrayOf(), byteArrayOf())
    val error = assertIs<RequestResult.NonSuccess<GetPreKeysError>>(responseFuture.get()).error
    assertIs<ServiceIdNotFoundException>(error)
  }
}
