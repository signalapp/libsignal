//
// Copyright (C) 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.libsignal.internal

import org.signal.libsignal.net.internal.BridgeChatListener
import org.signal.libsignal.net.internal.ConnectChatBridge
import org.signal.libsignal.protocol.SignedPublicPreKey
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.logging.Log
import org.signal.libsignal.protocol.logging.SignalProtocolLogger
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignedPreKeyStore
import org.signal.libsignal.protocol.util.Pair
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.util.Map
import java.util.UUID
import java.util.concurrent.Future

public typealias ObjectHandle = Long

private val tempDir: Path by lazy {
  val tempDir = Files.createTempDirectory("libsignal")
  tempDir.toFile().deleteOnExit()
  tempDir
}

internal object Native {
  init {
    loadNativeCode()
    initializeLibrary()
  }

  @Throws(IOException::class)
  private fun copyToTempDirAndLoad(
    input: InputStream,
    name: String,
  ) {
    val tempFile = Files.createFile(tempDir.resolve(name)).toFile()
    tempFile.deleteOnExit()

    FileOutputStream(tempFile).use { out ->
      val buffer = ByteArray(4096)

      while (true) {
        val read = input.read(buffer)
        if (read == -1) break
        out.write(buffer, 0, read)
      }
    }

    System.load(tempFile.absolutePath)
  }

  /**
    * If the library is embedded within this jar as a resource file, attempt to
    * copy it to a temporary file and then load it. This allows the jar to be
    * used even without a shared library existing on the filesystem.
    *
    * If a version of the library that includes this system's hardware architecture in its name is
    * present, prefer that to the supplied name (e.g. "libsignal_amd64.so" will be preferred to
    * "libsignal.so"). This applies only to libraries embedded as a resource, not libraries
    * installed on the local machine.
    */
  @Throws(IOException::class)
  private fun loadLibrary(name: String) {
    var arch = System.getProperty("os.arch")
    // Special-case: some Java implementations use "x86_64", but OpenJDK uses "amd64".
    if ("x86_64" == arch) {
      arch = "amd64"
    }
    for (suffix in arrayOf("_$arch", "")) {
      val libraryName = System.mapLibraryName(name + suffix)
      Native::class.java.getResourceAsStream("/$libraryName").use { input ->
        if (input != null) {
          copyToTempDirAndLoad(input, libraryName)
          return
        }
      }
    }
    System.loadLibrary(name)
  }

  private fun loadNativeCode() {
    try {
      // First try to load the testing library. This will only succeed when
      // libsignal is being used in a test context. The testing library
      // contains a superset of the functionality of the non-test library, so if
      // it gets loaded successfully, we're done.
      loadLibrary("signal_jni_testing")
      return
    } catch (_: Throwable) {
      // The testing library wasn't available. This is expected for production
      // builds, so no error handling is needed. We'll try to load the non-test
      // library next.
    }
    try {
      loadLibrary("signal_jni")
    } catch (e: Exception) {
      throw RuntimeException(e)
    }
  }

  /**
    * Ensures that the static initializer for this class gets run.
    */
  @JvmStatic
  internal fun ensureLoaded() {}

  /**
    * Keeps an object from being garbage-collected until this call completes.
    *
    * This can be used to keep a Java wrapper around a Rust object handle alive while
    * earlier calls use that Rust object handle. That is, you should call {@code keepAlive}
    * <em>after</em> the code where an object must not be garbage-collected.
    * However, most of the time {@link NativeHandleGuard} is a better choice,
    * since the lifetime of the guard is clear.
    *
    * Effectively equivalent to Java 9's <a href="https://docs.oracle.com/javase/9/docs/api/java/lang/ref/Reference.html#reachabilityFence-java.lang.Object-"><code>reachabilityFence()</code></a>.
    * Uses {@code native} because the JVM can't look into the implementation of the method
    * and optimize away the use of {@code obj}. (The actual implementation does nothing.)
    */
  @JvmStatic
  public external fun keepAlive(obj: Object?)

  @JvmStatic
  public external fun AccountEntropyPool_DeriveBackupKey(accountEntropy: String): ByteArray
  @JvmStatic
  public external fun AccountEntropyPool_DeriveSvrKey(accountEntropy: String): ByteArray
  @JvmStatic
  public external fun AccountEntropyPool_Generate(): String
  @JvmStatic
  public external fun AccountEntropyPool_IsValid(accountEntropy: String): Boolean

  @JvmStatic
  public external fun Aes256Ctr32_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256Ctr32_New(key: ByteArray, nonce: ByteArray, initialCtr: Int): ObjectHandle
  @JvmStatic
  public external fun Aes256Ctr32_Process(ctr: ObjectHandle, data: ByteArray, offset: Int, length: Int): Unit

  @JvmStatic
  public external fun Aes256GcmDecryption_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmDecryption_New(key: ByteArray, nonce: ByteArray, associatedData: ByteArray): ObjectHandle
  @JvmStatic
  public external fun Aes256GcmDecryption_Update(gcm: ObjectHandle, data: ByteArray, offset: Int, length: Int): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmDecryption_VerifyTag(gcm: ObjectHandle, tag: ByteArray): Boolean

  @JvmStatic
  public external fun Aes256GcmEncryption_ComputeTag(gcm: ObjectHandle): ByteArray
  @JvmStatic
  public external fun Aes256GcmEncryption_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmEncryption_New(key: ByteArray, nonce: ByteArray, associatedData: ByteArray): ObjectHandle
  @JvmStatic
  public external fun Aes256GcmEncryption_Update(gcm: ObjectHandle, data: ByteArray, offset: Int, length: Int): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmSiv_Decrypt(aesGcmSiv: ObjectHandle, ctext: ByteArray, nonce: ByteArray, associatedData: ByteArray): ByteArray
  @JvmStatic
  public external fun Aes256GcmSiv_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmSiv_Encrypt(aesGcmSivObj: ObjectHandle, ptext: ByteArray, nonce: ByteArray, associatedData: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun Aes256GcmSiv_New(key: ByteArray): ObjectHandle

  @JvmStatic
  public external fun AsyncLoadClass(tokioContext: Object, className: String): Object

  @JvmStatic @Throws(Exception::class)
  public external fun AuthCredentialPresentation_CheckValidContents(presentationBytes: ByteArray): Unit
  @JvmStatic
  public external fun AuthCredentialPresentation_GetPniCiphertext(presentationBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun AuthCredentialPresentation_GetRedemptionTime(presentationBytes: ByteArray): Long
  @JvmStatic
  public external fun AuthCredentialPresentation_GetUuidCiphertext(presentationBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun AuthCredentialWithPniResponse_CheckValidContents(bytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun AuthCredentialWithPni_CheckValidContents(bytes: ByteArray): Unit

  @JvmStatic
  public external fun AuthenticatedChatConnection_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun AuthenticatedChatConnection_connect(asyncRuntime: ObjectHandle, connectionManager: ObjectHandle, username: String, password: String, receiveStories: Boolean, languages: Array<Object>): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun AuthenticatedChatConnection_disconnect(asyncRuntime: ObjectHandle, chat: ObjectHandle): CompletableFuture<Void?>
  @JvmStatic
  public external fun AuthenticatedChatConnection_init_listener(chat: ObjectHandle, listener: BridgeChatListener): Unit
  @JvmStatic
  public external fun AuthenticatedChatConnection_preconnect(asyncRuntime: ObjectHandle, connectionManager: ObjectHandle): CompletableFuture<Void?>
  @JvmStatic
  public external fun AuthenticatedChatConnection_send(asyncRuntime: ObjectHandle, chat: ObjectHandle, httpRequest: ObjectHandle, timeoutMillis: Int): CompletableFuture<Object>

  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialPresentation_CheckValidContents(presentationBytes: ByteArray): Unit
  @JvmStatic
  public external fun BackupAuthCredentialPresentation_GetBackupId(presentationBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupAuthCredentialPresentation_GetBackupLevel(presentationBytes: ByteArray): Int
  @JvmStatic
  public external fun BackupAuthCredentialPresentation_GetType(presentationBytes: ByteArray): Int
  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialPresentation_Verify(presentationBytes: ByteArray, now: Long, serverParamsBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialRequestContext_CheckValidContents(contextBytes: ByteArray): Unit
  @JvmStatic
  public external fun BackupAuthCredentialRequestContext_GetRequest(contextBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupAuthCredentialRequestContext_New(backupKey: ByteArray, uuid: UUID): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialRequestContext_ReceiveResponse(contextBytes: ByteArray, responseBytes: ByteArray, expectedRedemptionTime: Long, paramsBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialRequest_CheckValidContents(requestBytes: ByteArray): Unit
  @JvmStatic
  public external fun BackupAuthCredentialRequest_IssueDeterministic(requestBytes: ByteArray, redemptionTime: Long, backupLevel: Int, credentialType: Int, paramsBytes: ByteArray, randomness: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredentialResponse_CheckValidContents(responseBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredential_CheckValidContents(paramsBytes: ByteArray): Unit
  @JvmStatic
  public external fun BackupAuthCredential_GetBackupId(credentialBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupAuthCredential_GetBackupLevel(credentialBytes: ByteArray): Int
  @JvmStatic
  public external fun BackupAuthCredential_GetType(credentialBytes: ByteArray): Int
  @JvmStatic @Throws(Exception::class)
  public external fun BackupAuthCredential_PresentDeterministic(credentialBytes: ByteArray, serverParamsBytes: ByteArray, randomness: ByteArray): ByteArray

  @JvmStatic
  public external fun BackupKey_DeriveBackupId(backupKey: ByteArray, aci: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupKey_DeriveEcKey(backupKey: ByteArray, aci: ByteArray): ObjectHandle
  @JvmStatic
  public external fun BackupKey_DeriveLocalBackupMetadataKey(backupKey: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupKey_DeriveMediaEncryptionKey(backupKey: ByteArray, mediaId: ByteArray): ByteArray
  @JvmStatic
  public external fun BackupKey_DeriveMediaId(backupKey: ByteArray, mediaName: String): ByteArray
  @JvmStatic
  public external fun BackupKey_DeriveThumbnailTransitEncryptionKey(backupKey: ByteArray, mediaId: ByteArray): ByteArray

  @JvmStatic
  public external fun BackupRestoreResponse_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun BackupRestoreResponse_GetForwardSecrecyToken(response: ObjectHandle): ByteArray
  @JvmStatic
  public external fun BackupRestoreResponse_GetNextBackupSecretData(response: ObjectHandle): ByteArray

  @JvmStatic
  public external fun BackupStoreResponse_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun BackupStoreResponse_GetForwardSecrecyToken(response: ObjectHandle): ByteArray
  @JvmStatic
  public external fun BackupStoreResponse_GetNextBackupSecretData(response: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun BackupStoreResponse_GetOpaqueMetadata(response: ObjectHandle): ByteArray

  @JvmStatic
  public external fun BridgedStringMap_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun BridgedStringMap_insert(map: ObjectHandle, key: String, value: String): Unit
  @JvmStatic
  public external fun BridgedStringMap_new(initialCapacity: Int): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredentialPresentation_CheckValidContents(presentationBytes: ByteArray): Unit
  @JvmStatic
  public external fun CallLinkAuthCredentialPresentation_GetUserId(presentationBytes: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredentialPresentation_Verify(presentationBytes: ByteArray, now: Long, serverParamsBytes: ByteArray, callLinkParamsBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredentialResponse_CheckValidContents(responseBytes: ByteArray): Unit
  @JvmStatic
  public external fun CallLinkAuthCredentialResponse_IssueDeterministic(userId: ByteArray, redemptionTime: Long, paramsBytes: ByteArray, randomness: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredentialResponse_Receive(responseBytes: ByteArray, userId: ByteArray, redemptionTime: Long, paramsBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredential_CheckValidContents(credentialBytes: ByteArray): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkAuthCredential_PresentDeterministic(credentialBytes: ByteArray, userId: ByteArray, redemptionTime: Long, serverParamsBytes: ByteArray, callLinkParamsBytes: ByteArray, randomness: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkPublicParams_CheckValidContents(paramsBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkSecretParams_CheckValidContents(paramsBytes: ByteArray): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun CallLinkSecretParams_DecryptUserId(paramsBytes: ByteArray, userId: ByteArray): ByteArray
  @JvmStatic
  public external fun CallLinkSecretParams_DeriveFromRootKey(rootKey: ByteArray): ByteArray
  @JvmStatic
  public external fun CallLinkSecretParams_EncryptUserId(paramsBytes: ByteArray, userId: ByteArray): ByteArray
  @JvmStatic
  public external fun CallLinkSecretParams_GetPublicParams(paramsBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun Cds2ClientState_New(mrenclave: ByteArray, attestationMsg: ByteArray, currentTimestamp: Long): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun Cds2Metrics_extract(attestationMsg: ByteArray): Map<*, *>

  @JvmStatic
  public external fun CdsiLookup_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun CdsiLookup_complete(asyncRuntime: ObjectHandle, lookup: ObjectHandle): CompletableFuture<Object>
  @JvmStatic
  public external fun CdsiLookup_new(asyncRuntime: ObjectHandle, connectionManager: ObjectHandle, username: String, password: String, request: ObjectHandle): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun CdsiLookup_token(lookup: ObjectHandle): ByteArray

  @JvmStatic
  public external fun ConnectionManager_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ConnectionManager_clear_proxy(connectionManager: ObjectHandle): Unit
  @JvmStatic
  public external fun ConnectionManager_new(environment: Int, userAgent: String, remoteConfig: ObjectHandle, buildVariant: Int): ObjectHandle
  @JvmStatic
  public external fun ConnectionManager_on_network_change(connectionManager: ObjectHandle): Unit
  @JvmStatic
  public external fun ConnectionManager_set_censorship_circumvention_enabled(connectionManager: ObjectHandle, enabled: Boolean): Unit
  @JvmStatic
  public external fun ConnectionManager_set_invalid_proxy(connectionManager: ObjectHandle): Unit
  @JvmStatic
  public external fun ConnectionManager_set_proxy(connectionManager: ObjectHandle, proxy: ObjectHandle): Unit
  @JvmStatic
  public external fun ConnectionManager_set_remote_config(connectionManager: ObjectHandle, remoteConfig: ObjectHandle, buildVariant: Int): Unit

  @JvmStatic
  public external fun ConnectionProxyConfig_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun ConnectionProxyConfig_new(scheme: String, host: String, port: Int, username: String?, password: String?): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialPresentation_CheckValidContents(presentationBytes: ByteArray): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialPresentation_Verify(presentationBytes: ByteArray, roomId: ByteArray, now: Long, serverParamsBytes: ByteArray, callLinkParamsBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialRequestContext_CheckValidContents(contextBytes: ByteArray): Unit
  @JvmStatic
  public external fun CreateCallLinkCredentialRequestContext_GetRequest(contextBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun CreateCallLinkCredentialRequestContext_NewDeterministic(roomId: ByteArray, randomness: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialRequestContext_ReceiveResponse(contextBytes: ByteArray, responseBytes: ByteArray, userId: ByteArray, paramsBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialRequest_CheckValidContents(requestBytes: ByteArray): Unit
  @JvmStatic
  public external fun CreateCallLinkCredentialRequest_IssueDeterministic(requestBytes: ByteArray, userId: ByteArray, timestamp: Long, paramsBytes: ByteArray, randomness: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredentialResponse_CheckValidContents(responseBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredential_CheckValidContents(paramsBytes: ByteArray): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun CreateCallLinkCredential_PresentDeterministic(credentialBytes: ByteArray, roomId: ByteArray, userId: ByteArray, serverParamsBytes: ByteArray, callLinkParamsBytes: ByteArray, randomness: ByteArray): ByteArray

  @JvmStatic
  public external fun CryptographicHash_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun CryptographicHash_Finalize(hash: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun CryptographicHash_New(algo: String): ObjectHandle
  @JvmStatic
  public external fun CryptographicHash_Update(hash: ObjectHandle, input: ByteArray): Unit
  @JvmStatic
  public external fun CryptographicHash_UpdateWithOffset(hash: ObjectHandle, input: ByteArray, offset: Int, len: Int): Unit

  @JvmStatic
  public external fun CryptographicMac_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun CryptographicMac_Finalize(mac: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun CryptographicMac_New(algo: String, key: ByteArray): ObjectHandle
  @JvmStatic
  public external fun CryptographicMac_Update(mac: ObjectHandle, input: ByteArray): Unit
  @JvmStatic
  public external fun CryptographicMac_UpdateWithOffset(mac: ObjectHandle, input: ByteArray, offset: Int, len: Int): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun DecryptionErrorMessage_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_ExtractFromSerializedContent(bytes: ByteArray): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_ForOriginalMessage(originalBytes: ByteArray, originalType: Int, originalTimestamp: Long, originalSenderDeviceId: Int): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_GetDeviceId(obj: ObjectHandle): Int
  @JvmStatic
  public external fun DecryptionErrorMessage_GetRatchetKey(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun DecryptionErrorMessage_GetTimestamp(obj: ObjectHandle): Long

  @JvmStatic @Throws(Exception::class)
  public external fun DeviceTransfer_GenerateCertificate(privateKey: ByteArray, name: String, daysToExpire: Int): ByteArray
  @JvmStatic
  public external fun DeviceTransfer_GeneratePrivateKey(): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_Agree(privateKey: ObjectHandle, publicKey: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ECPrivateKey_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ECPrivateKey_Generate(): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_GetPublicKey(k: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_HpkeOpen(sk: ObjectHandle, ciphertext: ByteArray, info: ByteArray, associatedData: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_Serialize(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ECPrivateKey_Sign(key: ObjectHandle, message: ByteArray): ByteArray

  @JvmStatic
  public external fun ECPublicKey_Compare(key1: ObjectHandle, key2: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun ECPublicKey_Deserialize(data: ByteArray, offset: Int, length: Int): ObjectHandle
  @JvmStatic
  public external fun ECPublicKey_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ECPublicKey_Equals(lhs: ObjectHandle, rhs: ObjectHandle): Boolean
  @JvmStatic @Throws(Exception::class)
  public external fun ECPublicKey_GetPublicKeyBytes(obj: ObjectHandle): ByteArray
  @JvmStatic
  public external fun ECPublicKey_HpkeSeal(pk: ObjectHandle, plaintext: ByteArray, info: ByteArray, associatedData: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ECPublicKey_Serialize(obj: ObjectHandle): ByteArray
  @JvmStatic
  public external fun ECPublicKey_Verify(key: ObjectHandle, message: ByteArray, signature: ByteArray): Boolean

  @JvmStatic @Throws(Exception::class)
  public external fun ExpiringProfileKeyCredentialResponse_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ExpiringProfileKeyCredential_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ExpiringProfileKeyCredential_GetExpirationTime(credential: ByteArray): Long

  @JvmStatic @Throws(Exception::class)
  public external fun GenericServerPublicParams_CheckValidContents(paramsBytes: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun GenericServerSecretParams_CheckValidContents(paramsBytes: ByteArray): Unit
  @JvmStatic
  public external fun GenericServerSecretParams_GenerateDeterministic(randomness: ByteArray): ByteArray
  @JvmStatic
  public external fun GenericServerSecretParams_GetPublicParams(paramsBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun GroupCipher_DecryptMessage(sender: ObjectHandle, message: ByteArray, store: SenderKeyStore): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun GroupCipher_EncryptMessage(sender: ObjectHandle, distributionId: UUID, message: ByteArray, store: SenderKeyStore): CiphertextMessage

  @JvmStatic @Throws(Exception::class)
  public external fun GroupMasterKey_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun GroupPublicParams_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun GroupPublicParams_GetGroupIdentifier(groupPublicParams: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSecretParams_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSecretParams_DecryptBlobWithPadding(params: ByteArray, ciphertext: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSecretParams_DecryptProfileKey(params: ByteArray, profileKey: ByteArray, userId: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSecretParams_DecryptServiceId(params: ByteArray, ciphertext: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_DeriveFromMasterKey(masterKey: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_EncryptBlobWithPaddingDeterministic(params: ByteArray, randomness: ByteArray, plaintext: ByteArray, paddingLen: Int): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_EncryptProfileKey(params: ByteArray, profileKey: ByteArray, userId: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_EncryptServiceId(params: ByteArray, serviceId: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_GenerateDeterministic(randomness: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_GetMasterKey(params: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSecretParams_GetPublicParams(params: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendDerivedKeyPair_CheckValidContents(bytes: ByteArray): Unit
  @JvmStatic
  public external fun GroupSendDerivedKeyPair_ForExpiration(expiration: Long, serverParams: ObjectHandle): ByteArray

  @JvmStatic
  public external fun GroupSendEndorsement_CallLinkParams_ToToken(endorsement: ByteArray, callLinkSecretParamsSerialized: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendEndorsement_CheckValidContents(bytes: ByteArray): Unit
  @JvmStatic
  public external fun GroupSendEndorsement_Combine(endorsements: Array<ByteBuffer>): ByteArray
  @JvmStatic
  public external fun GroupSendEndorsement_Remove(endorsement: ByteArray, toRemove: ByteArray): ByteArray
  @JvmStatic
  public external fun GroupSendEndorsement_ToToken(endorsement: ByteArray, groupParams: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendEndorsementsResponse_CheckValidContents(bytes: ByteArray): Unit
  @JvmStatic
  public external fun GroupSendEndorsementsResponse_GetExpiration(responseBytes: ByteArray): Long
  @JvmStatic
  public external fun GroupSendEndorsementsResponse_IssueDeterministic(concatenatedGroupMemberCiphertexts: ByteArray, keyPair: ByteArray, randomness: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(responseBytes: ByteArray, concatenatedGroupMemberCiphertexts: ByteArray, localUserCiphertext: ByteArray, now: Long, serverParams: ObjectHandle): Array<ByteArray>
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(responseBytes: ByteArray, groupMembers: ByteArray, localUser: ByteArray, now: Long, groupParams: ByteArray, serverParams: ObjectHandle): Array<ByteArray>

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendFullToken_CheckValidContents(bytes: ByteArray): Unit
  @JvmStatic
  public external fun GroupSendFullToken_GetExpiration(token: ByteArray): Long
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendFullToken_Verify(token: ByteArray, userIds: ByteArray, now: Long, keyPair: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSendToken_CheckValidContents(bytes: ByteArray): Unit
  @JvmStatic
  public external fun GroupSendToken_ToFullToken(token: ByteArray, expiration: Long): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun GroupSessionBuilder_CreateSenderKeyDistributionMessage(sender: ObjectHandle, distributionId: UUID, store: SenderKeyStore): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun GroupSessionBuilder_ProcessSenderKeyDistributionMessage(sender: ObjectHandle, senderKeyDistributionMessage: ObjectHandle, store: SenderKeyStore): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun HKDF_DeriveSecrets(outputLength: Int, ikm: ByteArray, label: ByteArray?, salt: ByteArray?): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun HsmEnclaveClient_CompleteHandshake(cli: ObjectHandle, handshakeReceived: ByteArray): Unit
  @JvmStatic
  public external fun HsmEnclaveClient_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun HsmEnclaveClient_EstablishedRecv(cli: ObjectHandle, receivedCiphertext: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun HsmEnclaveClient_EstablishedSend(cli: ObjectHandle, plaintextToSend: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun HsmEnclaveClient_InitialRequest(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun HsmEnclaveClient_New(trustedPublicKey: ByteArray, trustedCodeHashes: ByteArray): ObjectHandle

  @JvmStatic
  public external fun HttpRequest_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun HttpRequest_add_header(request: ObjectHandle, name: String, value: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun HttpRequest_new(method: String, path: String, bodyAsSlice: ByteArray?): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun IdentityKeyPair_Deserialize(input: ByteArray): Pair<ObjectHandle, ObjectHandle>
  @JvmStatic
  public external fun IdentityKeyPair_Serialize(publicKey: ObjectHandle, privateKey: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun IdentityKeyPair_SignAlternateIdentity(publicKey: ObjectHandle, privateKey: ObjectHandle, otherIdentity: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun IdentityKey_VerifyAlternateIdentity(publicKey: ObjectHandle, otherIdentity: ObjectHandle, signature: ByteArray): Boolean

  @JvmStatic
  public external fun IncrementalMac_CalculateChunkSize(dataSize: Int): Int
  @JvmStatic
  public external fun IncrementalMac_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun IncrementalMac_Finalize(mac: ObjectHandle): ByteArray
  @JvmStatic
  public external fun IncrementalMac_Initialize(key: ByteArray, chunkSize: Int): ObjectHandle
  @JvmStatic
  public external fun IncrementalMac_Update(mac: ObjectHandle, bytes: ByteArray, offset: Int, length: Int): ByteArray

  @JvmStatic
  public external fun KeyTransparency_AciSearchKey(aci: ByteArray): ByteArray
  @JvmStatic
  public external fun KeyTransparency_Distinguished(asyncRuntime: ObjectHandle, environment: Int, chatConnection: ObjectHandle, lastDistinguishedTreeHead: ByteArray?): CompletableFuture<ByteArray>
  @JvmStatic
  public external fun KeyTransparency_E164SearchKey(e164: String): ByteArray
  @JvmStatic
  public external fun KeyTransparency_Monitor(asyncRuntime: ObjectHandle, environment: Int, chatConnection: ObjectHandle, aci: ByteArray, aciIdentityKey: ObjectHandle, e164: String?, unidentifiedAccessKey: ByteArray?, usernameHash: ByteArray?, accountData: ByteArray?, lastDistinguishedTreeHead: ByteArray, isSelfMonitor: Boolean): CompletableFuture<ByteArray>
  @JvmStatic
  public external fun KeyTransparency_Search(asyncRuntime: ObjectHandle, environment: Int, chatConnection: ObjectHandle, aci: ByteArray, aciIdentityKey: ObjectHandle, e164: String?, unidentifiedAccessKey: ByteArray?, usernameHash: ByteArray?, accountData: ByteArray?, lastDistinguishedTreeHead: ByteArray): CompletableFuture<ByteArray>
  @JvmStatic
  public external fun KeyTransparency_UsernameHashSearchKey(hash: ByteArray): ByteArray

  @JvmStatic
  public external fun KyberKeyPair_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun KyberKeyPair_Generate(): ObjectHandle
  @JvmStatic
  public external fun KyberKeyPair_GetPublicKey(keyPair: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun KyberKeyPair_GetSecretKey(keyPair: ObjectHandle): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun KyberPreKeyRecord_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetKeyPair(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetPublicKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetSecretKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetSignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPreKeyRecord_GetTimestamp(obj: ObjectHandle): Long
  @JvmStatic
  public external fun KyberPreKeyRecord_New(id: Int, timestamp: Long, keyPair: ObjectHandle, signature: ByteArray): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun KyberPublicKey_DeserializeWithOffsetLength(data: ByteArray, offset: Int, length: Int): ObjectHandle
  @JvmStatic
  public external fun KyberPublicKey_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun KyberPublicKey_Equals(lhs: ObjectHandle, rhs: ObjectHandle): Boolean
  @JvmStatic @Throws(Exception::class)
  public external fun KyberPublicKey_Serialize(obj: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun KyberSecretKey_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun KyberSecretKey_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun KyberSecretKey_Serialize(obj: ObjectHandle): ByteArray

  @JvmStatic
  public external fun Logger_Initialize(maxLevel: Int, loggerClass: Class<*>): Unit
  @JvmStatic
  public external fun Logger_SetMaxLevel(maxLevel: Int): Unit

  @JvmStatic
  public external fun LookupRequest_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun LookupRequest_addAciAndAccessKey(request: ObjectHandle, aci: ByteArray, accessKey: ByteArray): Unit
  @JvmStatic
  public external fun LookupRequest_addE164(request: ObjectHandle, e164: String): Unit
  @JvmStatic
  public external fun LookupRequest_addPreviousE164(request: ObjectHandle, e164: String): Unit
  @JvmStatic
  public external fun LookupRequest_new(): ObjectHandle
  @JvmStatic
  public external fun LookupRequest_setToken(request: ObjectHandle, token: ByteArray): Unit

  @JvmStatic
  public external fun MessageBackupKey_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun MessageBackupKey_FromAccountEntropyPool(accountEntropy: String, aci: ByteArray, forwardSecrecyToken: ByteArray?): ObjectHandle
  @JvmStatic
  public external fun MessageBackupKey_FromBackupKeyAndBackupId(backupKey: ByteArray, backupId: ByteArray, forwardSecrecyToken: ByteArray?): ObjectHandle
  @JvmStatic
  public external fun MessageBackupKey_FromParts(hmacKey: ByteArray, aesKey: ByteArray): ObjectHandle
  @JvmStatic
  public external fun MessageBackupKey_GetAesKey(key: ObjectHandle): ByteArray
  @JvmStatic
  public external fun MessageBackupKey_GetHmacKey(key: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun MessageBackupValidator_Validate(key: ObjectHandle, firstStream: InputStream, secondStream: InputStream, len: Long, purpose: Int): Object

  @JvmStatic @Throws(Exception::class)
  public external fun Mp4Sanitizer_Sanitize(input: InputStream, len: Long): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun Mp4Sanitizer_Sanitize_File_With_Compounded_MDAT_Boxes(input: InputStream, len: Long, cumulativeMdatBoxSize: Int): ObjectHandle

  @JvmStatic
  public external fun NumericFingerprintGenerator_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun NumericFingerprintGenerator_GetDisplayString(obj: ObjectHandle): String
  @JvmStatic @Throws(Exception::class)
  public external fun NumericFingerprintGenerator_GetScannableEncoding(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun NumericFingerprintGenerator_New(iterations: Int, version: Int, localIdentifier: ByteArray, localKey: ObjectHandle, remoteIdentifier: ByteArray, remoteKey: ObjectHandle): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun OnlineBackupValidator_AddFrame(backup: ObjectHandle, frame: ByteArray): Unit
  @JvmStatic
  public external fun OnlineBackupValidator_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun OnlineBackupValidator_Finalize(backup: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun OnlineBackupValidator_New(backupInfoFrame: ByteArray, purpose: Int): ObjectHandle

  @JvmStatic
  public external fun PinHash_AccessKey(ph: ObjectHandle): ByteArray
  @JvmStatic
  public external fun PinHash_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun PinHash_EncryptionKey(ph: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun PinHash_FromSalt(pin: ByteArray, salt: ByteArray): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PinHash_FromUsernameMrenclave(pin: ByteArray, username: String, mrenclave: ByteArray): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun Pin_LocalHash(pin: ByteArray): String
  @JvmStatic @Throws(Exception::class)
  public external fun Pin_VerifyLocalHash(encodedHash: String, pin: ByteArray): Boolean

  @JvmStatic @Throws(Exception::class)
  public external fun PlaintextContent_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PlaintextContent_DeserializeAndGetContent(bytes: ByteArray): ByteArray
  @JvmStatic
  public external fun PlaintextContent_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun PlaintextContent_FromDecryptionErrorMessage(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PlaintextContent_GetBody(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun PlaintextContent_GetSerialized(obj: ObjectHandle): ByteArray

  @JvmStatic
  public external fun PreKeyBundle_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetDeviceId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetIdentityKey(p: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetKyberPreKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetKyberPreKeyPublic(bundle: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetKyberPreKeySignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetPreKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetPreKeyPublic(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetRegistrationId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetSignedPreKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetSignedPreKeyPublic(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_GetSignedPreKeySignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyBundle_New(registrationId: Int, deviceId: Int, prekeyId: Int, prekey: ObjectHandle, signedPrekeyId: Int, signedPrekey: ObjectHandle, signedPrekeySignature: ByteArray, identityKey: ObjectHandle, kyberPrekeyId: Int, kyberPrekey: ObjectHandle, kyberPrekeySignature: ByteArray): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyRecord_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun PreKeyRecord_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyRecord_GetId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyRecord_GetPrivateKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyRecord_GetPublicKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeyRecord_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic
  public external fun PreKeyRecord_New(id: Int, pubKey: ObjectHandle, privKey: ObjectHandle): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun PreKeySignalMessage_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun PreKeySignalMessage_GetBaseKey(m: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun PreKeySignalMessage_GetIdentityKey(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_GetPreKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_GetRegistrationId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic
  public external fun PreKeySignalMessage_GetSignalMessage(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_GetSignedPreKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_GetVersion(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun PreKeySignalMessage_New(messageVersion: Int, registrationId: Int, preKeyId: Int, signedPreKeyId: Int, baseKey: ObjectHandle, identityKey: ObjectHandle, signalMessage: ObjectHandle): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKeyCiphertext_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKeyCommitment_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKeyCredentialPresentation_CheckValidContents(presentationBytes: ByteArray): Unit
  @JvmStatic
  public external fun ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(presentationBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(presentationBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun ProfileKeyCredentialPresentation_GetUuidCiphertext(presentationBytes: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKeyCredentialRequestContext_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ProfileKeyCredentialRequestContext_GetRequest(context: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKeyCredentialRequest_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ProfileKey_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ProfileKey_DeriveAccessKey(profileKey: ByteArray): ByteArray
  @JvmStatic
  public external fun ProfileKey_GetCommitment(profileKey: ByteArray, userId: ByteArray): ByteArray
  @JvmStatic
  public external fun ProfileKey_GetProfileKeyVersion(profileKey: ByteArray, userId: ByteArray): ByteArray

  @JvmStatic
  public external fun ProtocolAddress_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ProtocolAddress_DeviceId(obj: ObjectHandle): Int
  @JvmStatic
  public external fun ProtocolAddress_Name(obj: ObjectHandle): String
  @JvmStatic @Throws(Exception::class)
  public external fun ProtocolAddress_New(name: String, deviceId: Int): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun ReceiptCredentialPresentation_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ReceiptCredentialPresentation_GetReceiptExpirationTime(presentation: ByteArray): Long
  @JvmStatic
  public external fun ReceiptCredentialPresentation_GetReceiptLevel(presentation: ByteArray): Long
  @JvmStatic
  public external fun ReceiptCredentialPresentation_GetReceiptSerial(presentation: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ReceiptCredentialRequestContext_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ReceiptCredentialRequestContext_GetRequest(requestContext: ByteArray): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ReceiptCredentialRequest_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ReceiptCredentialResponse_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ReceiptCredential_CheckValidContents(buffer: ByteArray): Unit
  @JvmStatic
  public external fun ReceiptCredential_GetReceiptExpirationTime(receiptCredential: ByteArray): Long
  @JvmStatic
  public external fun ReceiptCredential_GetReceiptLevel(receiptCredential: ByteArray): Long

  @JvmStatic
  public external fun RegisterAccountRequest_Create(): ObjectHandle
  @JvmStatic
  public external fun RegisterAccountRequest_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetAccountPassword(registerAccount: ObjectHandle, accountPassword: String): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetGcmPushToken(registerAccount: ObjectHandle, gcmPushToken: String): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetIdentityPqLastResortPreKey(registerAccount: ObjectHandle, identityType: Int, pqLastResortPreKey: SignedPublicPreKey<*>): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetIdentityPublicKey(registerAccount: ObjectHandle, identityType: Int, identityKey: ObjectHandle): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetIdentitySignedPreKey(registerAccount: ObjectHandle, identityType: Int, signedPreKey: SignedPublicPreKey<*>): Unit
  @JvmStatic
  public external fun RegisterAccountRequest_SetSkipDeviceTransfer(registerAccount: ObjectHandle): Unit

  @JvmStatic
  public external fun RegisterAccountResponse_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun RegisterAccountResponse_GetEntitlementBackupExpirationSeconds(response: ObjectHandle): Long
  @JvmStatic
  public external fun RegisterAccountResponse_GetEntitlementBackupLevel(response: ObjectHandle): Long
  @JvmStatic
  public external fun RegisterAccountResponse_GetEntitlementBadges(response: ObjectHandle): Array<Object>
  @JvmStatic
  public external fun RegisterAccountResponse_GetIdentity(response: ObjectHandle, identityType: Int): ByteArray
  @JvmStatic
  public external fun RegisterAccountResponse_GetNumber(response: ObjectHandle): String
  @JvmStatic
  public external fun RegisterAccountResponse_GetReregistration(response: ObjectHandle): Boolean
  @JvmStatic
  public external fun RegisterAccountResponse_GetStorageCapable(response: ObjectHandle): Boolean
  @JvmStatic
  public external fun RegisterAccountResponse_GetUsernameHash(response: ObjectHandle): ByteArray?
  @JvmStatic
  public external fun RegisterAccountResponse_GetUsernameLinkHandle(response: ObjectHandle): UUID?

  @JvmStatic
  public external fun RegistrationAccountAttributes_Create(recoveryPassword: ByteArray, aciRegistrationId: Int, pniRegistrationId: Int, registrationLock: String?, unidentifiedAccessKey: ByteArray, unrestrictedUnidentifiedAccess: Boolean, capabilities: Array<Object>, discoverableByPhoneNumber: Boolean): ObjectHandle
  @JvmStatic
  public external fun RegistrationAccountAttributes_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun RegistrationService_CheckSvr2Credentials(asyncRuntime: ObjectHandle, service: ObjectHandle, svrTokens: Array<Object>): CompletableFuture<Object>
  @JvmStatic
  public external fun RegistrationService_CreateSession(asyncRuntime: ObjectHandle, createSession: Object, connectChat: ConnectChatBridge): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun RegistrationService_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun RegistrationService_RegisterAccount(asyncRuntime: ObjectHandle, service: ObjectHandle, registerAccount: ObjectHandle, accountAttributes: ObjectHandle): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun RegistrationService_RegistrationSession(service: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun RegistrationService_RequestPushChallenge(asyncRuntime: ObjectHandle, service: ObjectHandle, pushToken: String): CompletableFuture<Void?>
  @JvmStatic
  public external fun RegistrationService_RequestVerificationCode(asyncRuntime: ObjectHandle, service: ObjectHandle, transport: String, client: String, languages: Array<Object>): CompletableFuture<Void?>
  @JvmStatic
  public external fun RegistrationService_ReregisterAccount(asyncRuntime: ObjectHandle, connectChat: ConnectChatBridge, number: String, registerAccount: ObjectHandle, accountAttributes: ObjectHandle): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun RegistrationService_ResumeSession(asyncRuntime: ObjectHandle, sessionId: String, number: String, connectChat: ConnectChatBridge): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun RegistrationService_SessionId(service: ObjectHandle): String
  @JvmStatic
  public external fun RegistrationService_SubmitCaptcha(asyncRuntime: ObjectHandle, service: ObjectHandle, captchaValue: String): CompletableFuture<Void?>
  @JvmStatic
  public external fun RegistrationService_SubmitPushChallenge(asyncRuntime: ObjectHandle, service: ObjectHandle, pushChallenge: String): CompletableFuture<Void?>
  @JvmStatic
  public external fun RegistrationService_SubmitVerificationCode(asyncRuntime: ObjectHandle, service: ObjectHandle, code: String): CompletableFuture<Void?>

  @JvmStatic
  public external fun RegistrationSession_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun RegistrationSession_GetAllowedToRequestCode(session: ObjectHandle): Boolean
  @JvmStatic
  public external fun RegistrationSession_GetNextCallSeconds(session: ObjectHandle): Int
  @JvmStatic
  public external fun RegistrationSession_GetNextSmsSeconds(session: ObjectHandle): Int
  @JvmStatic
  public external fun RegistrationSession_GetNextVerificationAttemptSeconds(session: ObjectHandle): Int
  @JvmStatic
  public external fun RegistrationSession_GetRequestedInformation(session: ObjectHandle): Array<Object>
  @JvmStatic
  public external fun RegistrationSession_GetVerified(session: ObjectHandle): Boolean

  @JvmStatic
  public external fun SanitizedMetadata_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun SanitizedMetadata_GetDataLen(sanitized: ObjectHandle): Long
  @JvmStatic
  public external fun SanitizedMetadata_GetDataOffset(sanitized: ObjectHandle): Long
  @JvmStatic
  public external fun SanitizedMetadata_GetMetadata(sanitized: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ScannableFingerprint_Compare(fprint1: ByteArray, fprint2: ByteArray): Boolean

  @JvmStatic
  public external fun SealedSender_MultiRecipientParseSentMessage(data: ByteArray): Object

  @JvmStatic @Throws(Exception::class)
  public external fun SealedSessionCipher_DecryptToUsmc(ctext: ByteArray, identityStore: IdentityKeyStore): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SealedSessionCipher_Encrypt(destination: ObjectHandle, content: ObjectHandle, identityKeyStore: IdentityKeyStore): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SealedSessionCipher_MultiRecipientEncrypt(recipients: LongArray, recipientSessions: LongArray, excludedRecipients: ByteArray, content: ObjectHandle, identityKeyStore: IdentityKeyStore): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SealedSessionCipher_MultiRecipientMessageForSingleRecipient(encodedMultiRecipientMessage: ByteArray): ByteArray

  @JvmStatic
  public external fun SecureValueRecoveryForBackups_CreateNewBackupChain(environment: Int, backupKey: ByteArray): ByteArray
  @JvmStatic
  public external fun SecureValueRecoveryForBackups_RemoveBackup(asyncRuntime: ObjectHandle, connectionManager: ObjectHandle, username: String, password: String): CompletableFuture<Void?>
  @JvmStatic
  public external fun SecureValueRecoveryForBackups_RestoreBackupFromServer(asyncRuntime: ObjectHandle, backupKey: ByteArray, metadata: ByteArray, connectionManager: ObjectHandle, username: String, password: String): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun SecureValueRecoveryForBackups_StoreBackup(asyncRuntime: ObjectHandle, backupKey: ByteArray, previousSecretData: ByteArray, connectionManager: ObjectHandle, username: String, password: String): CompletableFuture<ObjectHandle>

  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SenderCertificate_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetCertificate(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetDeviceId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetExpiration(obj: ObjectHandle): Long
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetSenderE164(obj: ObjectHandle): String?
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetSenderUuid(obj: ObjectHandle): String
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetServerCertificate(cert: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_GetSignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderCertificate_New(senderUuid: String, senderE164: String?, senderDeviceId: Int, senderKey: ObjectHandle, expiration: Long, signerCert: ObjectHandle, signerKey: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun SenderCertificate_Validate(cert: ObjectHandle, trustRoots: LongArray, time: Long): Boolean

  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SenderKeyDistributionMessage_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetChainId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetChainKey(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetDistributionId(obj: ObjectHandle): UUID
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetIteration(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_GetSignatureKey(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyDistributionMessage_New(messageVersion: Int, distributionId: UUID, chainId: Int, iteration: Int, chainkey: ByteArray, pk: ObjectHandle): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SenderKeyMessage_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_GetChainId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_GetCipherText(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_GetDistributionId(obj: ObjectHandle): UUID
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_GetIteration(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_New(messageVersion: Int, distributionId: UUID, chainId: Int, iteration: Int, ciphertext: ByteArray, pk: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyMessage_VerifySignature(skm: ObjectHandle, pubkey: ObjectHandle): Boolean

  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyRecord_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SenderKeyRecord_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SenderKeyRecord_GetSerialized(obj: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ServerCertificate_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_GetCertificate(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_GetKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_GetKeyId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_GetSignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerCertificate_New(keyId: Int, serverKey: ObjectHandle, trustRoot: ObjectHandle): ObjectHandle

  @JvmStatic
  public external fun ServerMessageAck_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun ServerMessageAck_Send(ack: ObjectHandle): Unit

  @JvmStatic
  public external fun ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(serverPublicParams: ObjectHandle, randomness: ByteArray, groupSecretParams: ByteArray, authCredentialWithPniBytes: ByteArray): ByteArray
  @JvmStatic
  public external fun ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(serverPublicParams: ObjectHandle, randomness: ByteArray, groupSecretParams: ByteArray, profileKeyCredential: ByteArray): ByteArray
  @JvmStatic
  public external fun ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(serverPublicParams: ObjectHandle, randomness: ByteArray, userId: ByteArray, profileKey: ByteArray): ByteArray
  @JvmStatic
  public external fun ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(serverPublicParams: ObjectHandle, randomness: ByteArray, receiptCredential: ByteArray): ByteArray
  @JvmStatic
  public external fun ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(serverPublicParams: ObjectHandle, randomness: ByteArray, receiptSerial: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerPublicParams_Deserialize(buffer: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ServerPublicParams_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ServerPublicParams_GetEndorsementPublicKey(params: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(params: ObjectHandle, aci: ByteArray, pni: ByteArray, redemptionTime: Long, authCredentialWithPniResponseBytes: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerPublicParams_ReceiveExpiringProfileKeyCredential(serverPublicParams: ObjectHandle, requestContext: ByteArray, response: ByteArray, currentTimeInSeconds: Long): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerPublicParams_ReceiveReceiptCredential(serverPublicParams: ObjectHandle, requestContext: ByteArray, response: ByteArray): ByteArray
  @JvmStatic
  public external fun ServerPublicParams_Serialize(handle: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerPublicParams_VerifySignature(serverPublicParams: ObjectHandle, message: ByteArray, notarySignature: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ServerSecretParams_Deserialize(buffer: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ServerSecretParams_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ServerSecretParams_GenerateDeterministic(randomness: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ServerSecretParams_GetPublicParams(params: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(serverSecretParams: ObjectHandle, randomness: ByteArray, aci: ByteArray, pni: ByteArray, redemptionTime: Long): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams: ObjectHandle, randomness: ByteArray, request: ByteArray, userId: ByteArray, commitment: ByteArray, expirationInSeconds: Long): ByteArray
  @JvmStatic
  public external fun ServerSecretParams_IssueReceiptCredentialDeterministic(serverSecretParams: ObjectHandle, randomness: ByteArray, request: ByteArray, receiptExpirationTime: Long, receiptLevel: Long): ByteArray
  @JvmStatic
  public external fun ServerSecretParams_Serialize(handle: ObjectHandle): ByteArray
  @JvmStatic
  public external fun ServerSecretParams_SignDeterministic(params: ObjectHandle, randomness: ByteArray, message: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams: ObjectHandle, groupPublicParams: ByteArray, presentationBytes: ByteArray, currentTimeInSeconds: Long): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams: ObjectHandle, groupPublicParams: ByteArray, presentationBytes: ByteArray, currentTimeInSeconds: Long): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun ServerSecretParams_VerifyReceiptCredentialPresentation(serverSecretParams: ObjectHandle, presentation: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun ServiceId_ParseFromServiceIdBinary(input: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun ServiceId_ParseFromServiceIdString(input: String): ByteArray
  @JvmStatic
  public external fun ServiceId_ServiceIdBinary(value: ByteArray): ByteArray
  @JvmStatic
  public external fun ServiceId_ServiceIdLog(value: ByteArray): String
  @JvmStatic
  public external fun ServiceId_ServiceIdString(value: ByteArray): String

  @JvmStatic @Throws(Exception::class)
  public external fun SessionBuilder_ProcessPreKeyBundle(bundle: ObjectHandle, protocolAddress: ObjectHandle, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Long): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun SessionCipher_DecryptPreKeySignalMessage(message: ObjectHandle, protocolAddress: ObjectHandle, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, kyberPrekeyStore: KyberPreKeyStore): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SessionCipher_DecryptSignalMessage(message: ObjectHandle, protocolAddress: ObjectHandle, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SessionCipher_EncryptMessage(ptext: ByteArray, protocolAddress: ObjectHandle, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, now: Long): CiphertextMessage

  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_ArchiveCurrentState(sessionRecord: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_CurrentRatchetKeyMatches(s: ObjectHandle, key: ObjectHandle): Boolean
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SessionRecord_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetLocalIdentityKeyPublic(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetLocalRegistrationId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetRemoteIdentityKeyPublic(obj: ObjectHandle): ByteArray?
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetRemoteRegistrationId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetSessionVersion(s: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_HasUsableSenderChain(s: ObjectHandle, now: Long): Boolean
  @JvmStatic
  public external fun SessionRecord_NewFresh(): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_Serialize(obj: ObjectHandle): ByteArray

  @JvmStatic @Throws(Exception::class)
  public external fun SgxClientState_CompleteHandshake(cli: ObjectHandle, handshakeReceived: ByteArray): Unit
  @JvmStatic
  public external fun SgxClientState_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SgxClientState_EstablishedRecv(cli: ObjectHandle, receivedCiphertext: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SgxClientState_EstablishedSend(cli: ObjectHandle, plaintextToSend: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SgxClientState_InitialRequest(obj: ObjectHandle): ByteArray

  @JvmStatic
  public external fun SignalMedia_CheckAvailable(): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SignalMessage_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_GetBody(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_GetCounter(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_GetMessageVersion(obj: ObjectHandle): Int
  @JvmStatic
  public external fun SignalMessage_GetPqRatchet(msg: ObjectHandle): ByteArray
  @JvmStatic
  public external fun SignalMessage_GetSenderRatchetKey(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_New(messageVersion: Int, macKey: ByteArray, senderRatchetKey: ObjectHandle, counter: Int, previousCounter: Int, ciphertext: ByteArray, senderIdentityKey: ObjectHandle, receiverIdentityKey: ObjectHandle, pqRatchet: ByteArray): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SignalMessage_VerifyMac(msg: ObjectHandle, senderIdentityKey: ObjectHandle, receiverIdentityKey: ObjectHandle, macKey: ByteArray): Boolean

  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun SignedPreKeyRecord_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetId(obj: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetPrivateKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetPublicKey(obj: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetSignature(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun SignedPreKeyRecord_GetTimestamp(obj: ObjectHandle): Long
  @JvmStatic
  public external fun SignedPreKeyRecord_New(id: Int, timestamp: Long, pubKey: ObjectHandle, privKey: ObjectHandle, signature: ByteArray): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun Svr2Client_New(mrenclave: ByteArray, attestationMsg: ByteArray, currentTimestamp: Long): ObjectHandle

  @JvmStatic
  public external fun TokioAsyncContext_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun TokioAsyncContext_cancel(context: ObjectHandle, rawCancellationId: Long): Unit
  @JvmStatic
  public external fun TokioAsyncContext_new(): ObjectHandle

  @JvmStatic
  public external fun UnauthenticatedChatConnection_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun UnauthenticatedChatConnection_connect(asyncRuntime: ObjectHandle, connectionManager: ObjectHandle, languages: Array<Object>): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun UnauthenticatedChatConnection_disconnect(asyncRuntime: ObjectHandle, chat: ObjectHandle): CompletableFuture<Void?>
  @JvmStatic
  public external fun UnauthenticatedChatConnection_info(chat: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun UnauthenticatedChatConnection_init_listener(chat: ObjectHandle, listener: BridgeChatListener): Unit
  @JvmStatic
  public external fun UnauthenticatedChatConnection_look_up_username_hash(asyncRuntime: ObjectHandle, chat: ObjectHandle, hash: ByteArray): CompletableFuture<UUID?>
  @JvmStatic
  public external fun UnauthenticatedChatConnection_look_up_username_link(asyncRuntime: ObjectHandle, chat: ObjectHandle, uuid: UUID, entropy: ByteArray): CompletableFuture<Pair<String, ByteArray>?>
  @JvmStatic
  public external fun UnauthenticatedChatConnection_send(asyncRuntime: ObjectHandle, chat: ObjectHandle, httpRequest: ObjectHandle, timeoutMillis: Int): CompletableFuture<Object>
  @JvmStatic
  public external fun UnauthenticatedChatConnection_send_multi_recipient_message(asyncRuntime: ObjectHandle, chat: ObjectHandle, payload: ByteArray, timestamp: Long, auth: ByteArray?, onlineOnly: Boolean, isUrgent: Boolean): CompletableFuture<Array<Object>>

  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_Deserialize(data: ByteArray): ObjectHandle
  @JvmStatic
  public external fun UnidentifiedSenderMessageContent_Destroy(handle: ObjectHandle): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetContentHint(m: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetContents(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetGroupId(obj: ObjectHandle): ByteArray?
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetMsgType(m: ObjectHandle): Int
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetSenderCert(m: ObjectHandle): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_GetSerialized(obj: ObjectHandle): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun UnidentifiedSenderMessageContent_New(message: CiphertextMessage, sender: ObjectHandle, contentHint: Int, groupId: ByteArray?): ObjectHandle

  @JvmStatic @Throws(Exception::class)
  public external fun UsernameLink_Create(username: String, entropy: ByteArray?): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun UsernameLink_DecryptUsername(entropy: ByteArray, encryptedUsername: ByteArray): String

  @JvmStatic @Throws(Exception::class)
  public external fun Username_CandidatesFrom(nickname: String, minLen: Int, maxLen: Int): Array<Object>
  @JvmStatic @Throws(Exception::class)
  public external fun Username_Hash(username: String): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun Username_HashFromParts(nickname: String, discriminator: String, minLen: Int, maxLen: Int): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun Username_Proof(username: String, randomness: ByteArray): ByteArray
  @JvmStatic @Throws(Exception::class)
  public external fun Username_Verify(proof: ByteArray, hash: ByteArray): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun UuidCiphertext_CheckValidContents(buffer: ByteArray): Unit

  @JvmStatic
  public external fun ValidatingMac_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ValidatingMac_Finalize(mac: ObjectHandle): Int
  @JvmStatic
  public external fun ValidatingMac_Initialize(key: ByteArray, chunkSize: Int, digests: ByteArray): ObjectHandle
  @JvmStatic
  public external fun ValidatingMac_Update(mac: ObjectHandle, bytes: ByteArray, offset: Int, length: Int): Int

  @JvmStatic @Throws(Exception::class)
  public external fun WebpSanitizer_Sanitize(input: InputStream): Unit

  @JvmStatic
  public external fun initializeLibrary(): Unit
}
