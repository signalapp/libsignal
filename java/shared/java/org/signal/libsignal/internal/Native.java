//
// Copyright (C) 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.libsignal.internal;

import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.logging.Log;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;
import org.signal.libsignal.net.internal.BridgeChatListener;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Future;
import java.util.UUID;
import java.util.Map;

public final class Native {
  private static Path tempDir;

  private static void copyToTempDirAndLoad(InputStream in, String name) throws IOException {
    // This isn't thread-safe but that's okay because it's only ever called from
    // static initializers, which are themselves thread-safe.
    if (tempDir == null) {
      tempDir = Files.createTempDirectory("libsignal");
      tempDir.toFile().deleteOnExit();
    }

    File tempFile = Files.createFile(tempDir.resolve(name)).toFile();
    tempFile.deleteOnExit();

    try (OutputStream out = new FileOutputStream(tempFile)) {
      byte[] buffer = new byte[4096];
      int read;

      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
      }
    }
    System.load(tempFile.getAbsolutePath());
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
   *
   * Package-private to allow the NativeTest class to load its shared library.
   * This method should only be called from a static initializer.
   */
  private static void loadLibrary(String name) throws IOException {
    String arch = System.getProperty("os.arch");
    // Special-case: some Java implementations use "x86_64", but OpenJDK uses "amd64".
    if ("x86_64".equals(arch)) {
      arch = "amd64";
    }
    for (String suffix : new String[]{ "_" + arch, "" }) {
      final String libraryName = System.mapLibraryName(name + suffix);
      try (InputStream in = Native.class.getResourceAsStream("/" + libraryName)) {
        if (in != null) {
          copyToTempDirAndLoad(in, libraryName);
          return;
        }
      }
    }
    System.loadLibrary(name);
  }

  private static void loadNativeCode() {
    try {
      // First try to load the testing library. This will only succeed when
      // libsignal is being used in a test context. The testing library
      // contains a superset of the functionality of the non-test library, so if
      // it gets loaded successfully, we're done.
      loadLibrary("signal_jni_testing");
      return;
    } catch (Throwable e) {
      // The testing library wasn't available. This is expected for production
      // builds, so no error handling is needed. We'll try to load the non-test
      // library next.
    }
    try {
      loadLibrary("signal_jni");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static {
    loadNativeCode();
    initializeLibrary();
  }

  /**
   * Ensures that the static initializer for this class gets run.
   */
  static void ensureLoaded() {}

  private Native() {}

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
  public static native void keepAlive(Object obj);

  public static native byte[] AccountEntropyPool_DeriveBackupKey(String accountEntropy);
  public static native byte[] AccountEntropyPool_DeriveSvrKey(String accountEntropy);
  public static native String AccountEntropyPool_Generate();
  public static native boolean AccountEntropyPool_IsValid(String accountEntropy);

  public static native void Aes256Ctr32_Destroy(long handle);
  public static native long Aes256Ctr32_New(byte[] key, byte[] nonce, int initialCtr) throws Exception;
  public static native void Aes256Ctr32_Process(long ctr, byte[] data, int offset, int length);

  public static native void Aes256GcmDecryption_Destroy(long handle);
  public static native long Aes256GcmDecryption_New(byte[] key, byte[] nonce, byte[] associatedData) throws Exception;
  public static native void Aes256GcmDecryption_Update(long gcm, byte[] data, int offset, int length);
  public static native boolean Aes256GcmDecryption_VerifyTag(long gcm, byte[] tag) throws Exception;

  public static native byte[] Aes256GcmEncryption_ComputeTag(long gcm);
  public static native void Aes256GcmEncryption_Destroy(long handle);
  public static native long Aes256GcmEncryption_New(byte[] key, byte[] nonce, byte[] associatedData) throws Exception;
  public static native void Aes256GcmEncryption_Update(long gcm, byte[] data, int offset, int length);

  public static native byte[] Aes256GcmSiv_Decrypt(long aesGcmSiv, byte[] ctext, byte[] nonce, byte[] associatedData) throws Exception;
  public static native void Aes256GcmSiv_Destroy(long handle);
  public static native byte[] Aes256GcmSiv_Encrypt(long aesGcmSivObj, byte[] ptext, byte[] nonce, byte[] associatedData) throws Exception;
  public static native long Aes256GcmSiv_New(byte[] key) throws Exception;

  public static native Object AsyncLoadClass(Object tokioContext, String className);

  public static native void AuthCredentialPresentation_CheckValidContents(byte[] presentationBytes) throws Exception;
  public static native byte[] AuthCredentialPresentation_GetPniCiphertext(byte[] presentationBytes);
  public static native long AuthCredentialPresentation_GetRedemptionTime(byte[] presentationBytes);
  public static native byte[] AuthCredentialPresentation_GetUuidCiphertext(byte[] presentationBytes);

  public static native void AuthCredentialWithPniResponse_CheckValidContents(byte[] bytes) throws Exception;

  public static native void AuthCredentialWithPni_CheckValidContents(byte[] bytes) throws Exception;

  public static native void AuthenticatedChatConnection_Destroy(long handle);
  public static native CompletableFuture<Long> AuthenticatedChatConnection_connect(long asyncRuntime, long connectionManager, String username, String password, boolean receiveStories);
  public static native CompletableFuture AuthenticatedChatConnection_disconnect(long asyncRuntime, long chat);
  public static native void AuthenticatedChatConnection_init_listener(long chat, BridgeChatListener listener);
  public static native CompletableFuture<Object> AuthenticatedChatConnection_send(long asyncRuntime, long chat, long httpRequest, int timeoutMillis);

  public static native void BackupAuthCredentialPresentation_CheckValidContents(byte[] presentationBytes) throws Exception;
  public static native byte[] BackupAuthCredentialPresentation_GetBackupId(byte[] presentationBytes);
  public static native int BackupAuthCredentialPresentation_GetBackupLevel(byte[] presentationBytes);
  public static native int BackupAuthCredentialPresentation_GetType(byte[] presentationBytes);
  public static native void BackupAuthCredentialPresentation_Verify(byte[] presentationBytes, long now, byte[] serverParamsBytes) throws Exception;

  public static native void BackupAuthCredentialRequestContext_CheckValidContents(byte[] contextBytes) throws Exception;
  public static native byte[] BackupAuthCredentialRequestContext_GetRequest(byte[] contextBytes);
  public static native byte[] BackupAuthCredentialRequestContext_New(byte[] backupKey, UUID uuid);
  public static native byte[] BackupAuthCredentialRequestContext_ReceiveResponse(byte[] contextBytes, byte[] responseBytes, long expectedRedemptionTime, byte[] paramsBytes) throws Exception;

  public static native void BackupAuthCredentialRequest_CheckValidContents(byte[] requestBytes) throws Exception;
  public static native byte[] BackupAuthCredentialRequest_IssueDeterministic(byte[] requestBytes, long redemptionTime, int backupLevel, int credentialType, byte[] paramsBytes, byte[] randomness);

  public static native void BackupAuthCredentialResponse_CheckValidContents(byte[] responseBytes) throws Exception;

  public static native void BackupAuthCredential_CheckValidContents(byte[] paramsBytes) throws Exception;
  public static native byte[] BackupAuthCredential_GetBackupId(byte[] credentialBytes);
  public static native int BackupAuthCredential_GetBackupLevel(byte[] credentialBytes);
  public static native int BackupAuthCredential_GetType(byte[] credentialBytes);
  public static native byte[] BackupAuthCredential_PresentDeterministic(byte[] credentialBytes, byte[] serverParamsBytes, byte[] randomness) throws Exception;

  public static native byte[] BackupKey_DeriveBackupId(byte[] backupKey, byte[] aci);
  public static native long BackupKey_DeriveEcKey(byte[] backupKey, byte[] aci);
  public static native byte[] BackupKey_DeriveLocalBackupMetadataKey(byte[] backupKey);
  public static native byte[] BackupKey_DeriveMediaEncryptionKey(byte[] backupKey, byte[] mediaId);
  public static native byte[] BackupKey_DeriveMediaId(byte[] backupKey, String mediaName);
  public static native byte[] BackupKey_DeriveThumbnailTransitEncryptionKey(byte[] backupKey, byte[] mediaId);

  public static native void CallLinkAuthCredentialPresentation_CheckValidContents(byte[] presentationBytes) throws Exception;
  public static native byte[] CallLinkAuthCredentialPresentation_GetUserId(byte[] presentationBytes);
  public static native void CallLinkAuthCredentialPresentation_Verify(byte[] presentationBytes, long now, byte[] serverParamsBytes, byte[] callLinkParamsBytes) throws Exception;

  public static native void CallLinkAuthCredentialResponse_CheckValidContents(byte[] responseBytes) throws Exception;
  public static native byte[] CallLinkAuthCredentialResponse_IssueDeterministic(byte[] userId, long redemptionTime, byte[] paramsBytes, byte[] randomness);
  public static native byte[] CallLinkAuthCredentialResponse_Receive(byte[] responseBytes, byte[] userId, long redemptionTime, byte[] paramsBytes) throws Exception;

  public static native void CallLinkAuthCredential_CheckValidContents(byte[] credentialBytes) throws Exception;
  public static native byte[] CallLinkAuthCredential_PresentDeterministic(byte[] credentialBytes, byte[] userId, long redemptionTime, byte[] serverParamsBytes, byte[] callLinkParamsBytes, byte[] randomness) throws Exception;

  public static native void CallLinkPublicParams_CheckValidContents(byte[] paramsBytes) throws Exception;

  public static native void CallLinkSecretParams_CheckValidContents(byte[] paramsBytes) throws Exception;
  public static native byte[] CallLinkSecretParams_DecryptUserId(byte[] paramsBytes, byte[] userId) throws Exception;
  public static native byte[] CallLinkSecretParams_DeriveFromRootKey(byte[] rootKey);
  public static native byte[] CallLinkSecretParams_GetPublicParams(byte[] paramsBytes);

  public static native long Cds2ClientState_New(byte[] mrenclave, byte[] attestationMsg, long currentTimestamp) throws Exception;

  public static native Map Cds2Metrics_extract(byte[] attestationMsg) throws Exception;

  public static native void CdsiLookup_Destroy(long handle);
  public static native CompletableFuture<Object> CdsiLookup_complete(long asyncRuntime, long lookup);
  public static native CompletableFuture<Long> CdsiLookup_new(long asyncRuntime, long connectionManager, String username, String password, long request);
  public static native CompletableFuture<Long> CdsiLookup_new_routes(long asyncRuntime, long connectionManager, String username, String password, long request);
  public static native byte[] CdsiLookup_token(long lookup);

  public static native void ConnectionManager_Destroy(long handle);
  public static native void ConnectionManager_clear_proxy(long connectionManager);
  public static native long ConnectionManager_new(int environment, String userAgent);
  public static native void ConnectionManager_on_network_change(long connectionManager);
  public static native void ConnectionManager_set_censorship_circumvention_enabled(long connectionManager, boolean enabled);
  public static native void ConnectionManager_set_invalid_proxy(long connectionManager);
  public static native void ConnectionManager_set_proxy(long connectionManager, long proxy);

  public static native void ConnectionProxyConfig_Destroy(long handle);
  public static native long ConnectionProxyConfig_new(String scheme, String host, int port, String username, String password) throws Exception;

  public static native void CreateCallLinkCredentialPresentation_CheckValidContents(byte[] presentationBytes) throws Exception;
  public static native void CreateCallLinkCredentialPresentation_Verify(byte[] presentationBytes, byte[] roomId, long now, byte[] serverParamsBytes, byte[] callLinkParamsBytes) throws Exception;

  public static native void CreateCallLinkCredentialRequestContext_CheckValidContents(byte[] contextBytes) throws Exception;
  public static native byte[] CreateCallLinkCredentialRequestContext_GetRequest(byte[] contextBytes);
  public static native byte[] CreateCallLinkCredentialRequestContext_NewDeterministic(byte[] roomId, byte[] randomness);
  public static native byte[] CreateCallLinkCredentialRequestContext_ReceiveResponse(byte[] contextBytes, byte[] responseBytes, byte[] userId, byte[] paramsBytes) throws Exception;

  public static native void CreateCallLinkCredentialRequest_CheckValidContents(byte[] requestBytes) throws Exception;
  public static native byte[] CreateCallLinkCredentialRequest_IssueDeterministic(byte[] requestBytes, byte[] userId, long timestamp, byte[] paramsBytes, byte[] randomness);

  public static native void CreateCallLinkCredentialResponse_CheckValidContents(byte[] responseBytes) throws Exception;

  public static native void CreateCallLinkCredential_CheckValidContents(byte[] paramsBytes) throws Exception;
  public static native byte[] CreateCallLinkCredential_PresentDeterministic(byte[] credentialBytes, byte[] roomId, byte[] userId, byte[] serverParamsBytes, byte[] callLinkParamsBytes, byte[] randomness) throws Exception;

  public static native String CreateOTP(String username, byte[] secret);

  public static native String CreateOTPFromBase64(String username, String secret);

  public static native void CryptographicHash_Destroy(long handle);
  public static native byte[] CryptographicHash_Finalize(long hash);
  public static native long CryptographicHash_New(String algo) throws Exception;
  public static native void CryptographicHash_Update(long hash, byte[] input);
  public static native void CryptographicHash_UpdateWithOffset(long hash, byte[] input, int offset, int len);

  public static native void CryptographicMac_Destroy(long handle);
  public static native byte[] CryptographicMac_Finalize(long mac);
  public static native long CryptographicMac_New(String algo, byte[] key) throws Exception;
  public static native void CryptographicMac_Update(long mac, byte[] input);
  public static native void CryptographicMac_UpdateWithOffset(long mac, byte[] input, int offset, int len);

  public static native long DecryptionErrorMessage_Deserialize(byte[] data) throws Exception;
  public static native void DecryptionErrorMessage_Destroy(long handle);
  public static native long DecryptionErrorMessage_ExtractFromSerializedContent(byte[] bytes) throws Exception;
  public static native long DecryptionErrorMessage_ForOriginalMessage(byte[] originalBytes, int originalType, long originalTimestamp, int originalSenderDeviceId) throws Exception;
  public static native int DecryptionErrorMessage_GetDeviceId(long obj) throws Exception;
  public static native long DecryptionErrorMessage_GetRatchetKey(long m);
  public static native byte[] DecryptionErrorMessage_GetSerialized(long obj) throws Exception;
  public static native long DecryptionErrorMessage_GetTimestamp(long obj) throws Exception;

  public static native byte[] DeviceTransfer_GenerateCertificate(byte[] privateKey, String name, int daysToExpire) throws Exception;
  public static native byte[] DeviceTransfer_GeneratePrivateKey();

  public static native byte[] ECPrivateKey_Agree(long privateKey, long publicKey) throws Exception;
  public static native long ECPrivateKey_Deserialize(byte[] data) throws Exception;
  public static native void ECPrivateKey_Destroy(long handle);
  public static native long ECPrivateKey_Generate();
  public static native long ECPrivateKey_GetPublicKey(long k) throws Exception;
  public static native byte[] ECPrivateKey_Serialize(long obj) throws Exception;
  public static native byte[] ECPrivateKey_Sign(long key, byte[] message) throws Exception;

  public static native int ECPublicKey_Compare(long key1, long key2);
  public static native long ECPublicKey_Deserialize(byte[] data, int offset) throws Exception;
  public static native void ECPublicKey_Destroy(long handle);
  public static native boolean ECPublicKey_Equals(long lhs, long rhs);
  public static native byte[] ECPublicKey_GetPublicKeyBytes(long obj) throws Exception;
  public static native byte[] ECPublicKey_Serialize(long obj) throws Exception;
  public static native boolean ECPublicKey_Verify(long key, byte[] message, byte[] signature);

  public static native void ExpiringProfileKeyCredentialResponse_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ExpiringProfileKeyCredential_CheckValidContents(byte[] buffer) throws Exception;
  public static native long ExpiringProfileKeyCredential_GetExpirationTime(byte[] credential);

  public static native void GenericServerPublicParams_CheckValidContents(byte[] paramsBytes) throws Exception;

  public static native void GenericServerSecretParams_CheckValidContents(byte[] paramsBytes) throws Exception;
  public static native byte[] GenericServerSecretParams_GenerateDeterministic(byte[] randomness);
  public static native byte[] GenericServerSecretParams_GetPublicParams(byte[] paramsBytes);

  public static native byte[] GroupCipher_DecryptMessage(long sender, byte[] message, SenderKeyStore store) throws Exception;
  public static native CiphertextMessage GroupCipher_EncryptMessage(long sender, UUID distributionId, byte[] message, SenderKeyStore store) throws Exception;

  public static native void GroupMasterKey_CheckValidContents(byte[] buffer) throws Exception;

  public static native void GroupPublicParams_CheckValidContents(byte[] buffer) throws Exception;
  public static native byte[] GroupPublicParams_GetGroupIdentifier(byte[] groupPublicParams);

  public static native void GroupSecretParams_CheckValidContents(byte[] buffer) throws Exception;
  public static native byte[] GroupSecretParams_DecryptBlobWithPadding(byte[] params, byte[] ciphertext) throws Exception;
  public static native byte[] GroupSecretParams_DecryptProfileKey(byte[] params, byte[] profileKey, byte[] userId) throws Exception;
  public static native byte[] GroupSecretParams_DecryptServiceId(byte[] params, byte[] ciphertext) throws Exception;
  public static native byte[] GroupSecretParams_DeriveFromMasterKey(byte[] masterKey);
  public static native byte[] GroupSecretParams_EncryptBlobWithPaddingDeterministic(byte[] params, byte[] randomness, byte[] plaintext, int paddingLen);
  public static native byte[] GroupSecretParams_EncryptProfileKey(byte[] params, byte[] profileKey, byte[] userId);
  public static native byte[] GroupSecretParams_EncryptServiceId(byte[] params, byte[] serviceId);
  public static native byte[] GroupSecretParams_GenerateDeterministic(byte[] randomness);
  public static native byte[] GroupSecretParams_GetMasterKey(byte[] params);
  public static native byte[] GroupSecretParams_GetPublicParams(byte[] params);

  public static native void GroupSendDerivedKeyPair_CheckValidContents(byte[] bytes) throws Exception;
  public static native byte[] GroupSendDerivedKeyPair_ForExpiration(long expiration, long serverParams);

  public static native void GroupSendEndorsement_CheckValidContents(byte[] bytes) throws Exception;
  public static native byte[] GroupSendEndorsement_Combine(ByteBuffer[] endorsements);
  public static native byte[] GroupSendEndorsement_Remove(byte[] endorsement, byte[] toRemove);
  public static native byte[] GroupSendEndorsement_ToToken(byte[] endorsement, byte[] groupParams);

  public static native void GroupSendEndorsementsResponse_CheckValidContents(byte[] bytes) throws Exception;
  public static native long GroupSendEndorsementsResponse_GetExpiration(byte[] responseBytes);
  public static native byte[] GroupSendEndorsementsResponse_IssueDeterministic(byte[] concatenatedGroupMemberCiphertexts, byte[] keyPair, byte[] randomness);
  public static native byte[][] GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(byte[] responseBytes, byte[] concatenatedGroupMemberCiphertexts, byte[] localUserCiphertext, long now, long serverParams) throws Exception;
  public static native byte[][] GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(byte[] responseBytes, byte[] groupMembers, byte[] localUser, long now, byte[] groupParams, long serverParams) throws Exception;

  public static native void GroupSendFullToken_CheckValidContents(byte[] bytes) throws Exception;
  public static native long GroupSendFullToken_GetExpiration(byte[] token);
  public static native void GroupSendFullToken_Verify(byte[] token, byte[] userIds, long now, byte[] keyPair) throws Exception;

  public static native void GroupSendToken_CheckValidContents(byte[] bytes) throws Exception;
  public static native byte[] GroupSendToken_ToFullToken(byte[] token, long expiration);

  public static native long GroupSessionBuilder_CreateSenderKeyDistributionMessage(long sender, UUID distributionId, SenderKeyStore store) throws Exception;
  public static native void GroupSessionBuilder_ProcessSenderKeyDistributionMessage(long sender, long senderKeyDistributionMessage, SenderKeyStore store) throws Exception;

  public static native byte[] HKDF_DeriveSecrets(int outputLength, byte[] ikm, byte[] label, byte[] salt) throws Exception;

  public static native void HsmEnclaveClient_CompleteHandshake(long cli, byte[] handshakeReceived) throws Exception;
  public static native void HsmEnclaveClient_Destroy(long handle);
  public static native byte[] HsmEnclaveClient_EstablishedRecv(long cli, byte[] receivedCiphertext) throws Exception;
  public static native byte[] HsmEnclaveClient_EstablishedSend(long cli, byte[] plaintextToSend) throws Exception;
  public static native byte[] HsmEnclaveClient_InitialRequest(long obj) throws Exception;
  public static native long HsmEnclaveClient_New(byte[] trustedPublicKey, byte[] trustedCodeHashes) throws Exception;

  public static native void HttpRequest_Destroy(long handle);
  public static native void HttpRequest_add_header(long request, String name, String value);
  public static native long HttpRequest_new(String method, String path, byte[] bodyAsSlice) throws Exception;

  public static native long[] IdentityKeyPair_Deserialize(byte[] data);
  public static native byte[] IdentityKeyPair_Serialize(long publicKey, long privateKey);
  public static native byte[] IdentityKeyPair_SignAlternateIdentity(long publicKey, long privateKey, long otherIdentity) throws Exception;

  public static native boolean IdentityKey_VerifyAlternateIdentity(long publicKey, long otherIdentity, byte[] signature) throws Exception;

  public static native int IncrementalMac_CalculateChunkSize(int dataSize);
  public static native void IncrementalMac_Destroy(long handle);
  public static native byte[] IncrementalMac_Finalize(long mac);
  public static native long IncrementalMac_Initialize(byte[] key, int chunkSize);
  public static native byte[] IncrementalMac_Update(long mac, byte[] bytes, int offset, int length);

  public static native byte[] KeyTransparency_AciSearchKey(byte[] aci);
  public static native CompletableFuture<byte[]> KeyTransparency_Distinguished(long asyncRuntime, int environment, long chatConnection, byte[] lastDistinguishedTreeHead);
  public static native byte[] KeyTransparency_E164SearchKey(String e164);
  public static native CompletableFuture<byte[]> KeyTransparency_Monitor(long asyncRuntime, int environment, long chatConnection, byte[] aci, long aciIdentityKey, String e164, byte[] unidentifiedAccessKey, byte[] usernameHash, byte[] accountData, byte[] lastDistinguishedTreeHead);
  public static native CompletableFuture<Long> KeyTransparency_Search(long asyncRuntime, int environment, long chatConnection, byte[] aci, long aciIdentityKey, String e164, byte[] unidentifiedAccessKey, byte[] usernameHash, byte[] accountData, byte[] lastDistinguishedTreeHead);
  public static native byte[] KeyTransparency_UsernameHashSearchKey(byte[] hash);

  public static native void KyberKeyPair_Destroy(long handle);
  public static native long KyberKeyPair_Generate();
  public static native long KyberKeyPair_GetPublicKey(long keyPair);
  public static native long KyberKeyPair_GetSecretKey(long keyPair);

  public static native long KyberPreKeyRecord_Deserialize(byte[] data) throws Exception;
  public static native void KyberPreKeyRecord_Destroy(long handle);
  public static native int KyberPreKeyRecord_GetId(long obj) throws Exception;
  public static native long KyberPreKeyRecord_GetKeyPair(long obj) throws Exception;
  public static native long KyberPreKeyRecord_GetPublicKey(long obj) throws Exception;
  public static native long KyberPreKeyRecord_GetSecretKey(long obj) throws Exception;
  public static native byte[] KyberPreKeyRecord_GetSerialized(long obj) throws Exception;
  public static native byte[] KyberPreKeyRecord_GetSignature(long obj) throws Exception;
  public static native long KyberPreKeyRecord_GetTimestamp(long obj) throws Exception;
  public static native long KyberPreKeyRecord_New(int id, long timestamp, long keyPair, byte[] signature);

  public static native long KyberPublicKey_DeserializeWithOffset(byte[] data, int offset) throws Exception;
  public static native void KyberPublicKey_Destroy(long handle);
  public static native boolean KyberPublicKey_Equals(long lhs, long rhs);
  public static native byte[] KyberPublicKey_Serialize(long obj) throws Exception;

  public static native long KyberSecretKey_Deserialize(byte[] data) throws Exception;
  public static native void KyberSecretKey_Destroy(long handle);
  public static native byte[] KyberSecretKey_Serialize(long obj) throws Exception;

  public static native void Logger_Initialize(int maxLevel, Class loggerClass);
  public static native void Logger_SetMaxLevel(int maxLevel);

  public static native void LookupRequest_Destroy(long handle);
  public static native void LookupRequest_addAciAndAccessKey(long request, byte[] aci, byte[] accessKey) throws Exception;
  public static native void LookupRequest_addE164(long request, String e164);
  public static native void LookupRequest_addPreviousE164(long request, String e164);
  public static native long LookupRequest_new();
  public static native void LookupRequest_setToken(long request, byte[] token);

  public static native void MessageBackupKey_Destroy(long handle);
  public static native long MessageBackupKey_FromAccountEntropyPool(String accountEntropy, byte[] aci);
  public static native long MessageBackupKey_FromBackupKeyAndBackupId(byte[] backupKey, byte[] backupId);
  public static native long MessageBackupKey_FromMasterKey(byte[] masterKey, byte[] aci);
  public static native long MessageBackupKey_FromParts(byte[] hmacKey, byte[] aesKey);
  public static native byte[] MessageBackupKey_GetAesKey(long key);
  public static native byte[] MessageBackupKey_GetHmacKey(long key);

  public static native Object MessageBackupValidator_Validate(long key, InputStream firstStream, InputStream secondStream, long len, int purpose) throws Exception;

  public static native long Mp4Sanitizer_Sanitize(InputStream input, long len) throws Exception;
  public static native long Mp4Sanitizer_Sanitize_File_With_Compounded_MDAT_Boxes(InputStream input, long len, int cumulativeMdatBoxSize) throws Exception;

  public static native void NumericFingerprintGenerator_Destroy(long handle);
  public static native String NumericFingerprintGenerator_GetDisplayString(long obj) throws Exception;
  public static native byte[] NumericFingerprintGenerator_GetScannableEncoding(long obj) throws Exception;
  public static native long NumericFingerprintGenerator_New(int iterations, int version, byte[] localIdentifier, byte[] localKey, byte[] remoteIdentifier, byte[] remoteKey) throws Exception;

  public static native void OnlineBackupValidator_AddFrame(long backup, byte[] frame) throws Exception;
  public static native void OnlineBackupValidator_Destroy(long handle);
  public static native void OnlineBackupValidator_Finalize(long backup) throws Exception;
  public static native long OnlineBackupValidator_New(byte[] backupInfoFrame, int purpose) throws Exception;

  public static native byte[] PinHash_AccessKey(long ph);
  public static native void PinHash_Destroy(long handle);
  public static native byte[] PinHash_EncryptionKey(long ph);
  public static native long PinHash_FromSalt(byte[] pin, byte[] salt) throws Exception;
  public static native long PinHash_FromUsernameMrenclave(byte[] pin, String username, byte[] mrenclave) throws Exception;

  public static native String Pin_LocalHash(byte[] pin) throws Exception;
  public static native boolean Pin_VerifyLocalHash(String encodedHash, byte[] pin) throws Exception;

  public static native long PlaintextContent_Deserialize(byte[] data) throws Exception;
  public static native byte[] PlaintextContent_DeserializeAndGetContent(byte[] bytes) throws Exception;
  public static native void PlaintextContent_Destroy(long handle);
  public static native long PlaintextContent_FromDecryptionErrorMessage(long m);
  public static native byte[] PlaintextContent_GetBody(long obj) throws Exception;
  public static native byte[] PlaintextContent_GetSerialized(long obj) throws Exception;

  public static native void PreKeyBundle_Destroy(long handle);
  public static native int PreKeyBundle_GetDeviceId(long obj) throws Exception;
  public static native long PreKeyBundle_GetIdentityKey(long p) throws Exception;
  public static native int PreKeyBundle_GetKyberPreKeyId(long obj) throws Exception;
  public static native long PreKeyBundle_GetKyberPreKeyPublic(long bundle) throws Exception;
  public static native byte[] PreKeyBundle_GetKyberPreKeySignature(long bundle) throws Exception;
  public static native int PreKeyBundle_GetPreKeyId(long obj) throws Exception;
  public static native long PreKeyBundle_GetPreKeyPublic(long obj) throws Exception;
  public static native int PreKeyBundle_GetRegistrationId(long obj) throws Exception;
  public static native int PreKeyBundle_GetSignedPreKeyId(long obj) throws Exception;
  public static native long PreKeyBundle_GetSignedPreKeyPublic(long obj) throws Exception;
  public static native byte[] PreKeyBundle_GetSignedPreKeySignature(long obj) throws Exception;
  public static native long PreKeyBundle_New(int registrationId, int deviceId, int prekeyId, long prekey, int signedPrekeyId, long signedPrekey, byte[] signedPrekeySignature, long identityKey, int kyberPrekeyId, long kyberPrekey, byte[] kyberPrekeySignature) throws Exception;

  public static native long PreKeyRecord_Deserialize(byte[] data) throws Exception;
  public static native void PreKeyRecord_Destroy(long handle);
  public static native int PreKeyRecord_GetId(long obj) throws Exception;
  public static native long PreKeyRecord_GetPrivateKey(long obj) throws Exception;
  public static native long PreKeyRecord_GetPublicKey(long obj) throws Exception;
  public static native byte[] PreKeyRecord_GetSerialized(long obj) throws Exception;
  public static native long PreKeyRecord_New(int id, long pubKey, long privKey);

  public static native long PreKeySignalMessage_Deserialize(byte[] data) throws Exception;
  public static native void PreKeySignalMessage_Destroy(long handle);
  public static native long PreKeySignalMessage_GetBaseKey(long m);
  public static native long PreKeySignalMessage_GetIdentityKey(long m);
  public static native int PreKeySignalMessage_GetPreKeyId(long obj) throws Exception;
  public static native int PreKeySignalMessage_GetRegistrationId(long obj) throws Exception;
  public static native byte[] PreKeySignalMessage_GetSerialized(long obj) throws Exception;
  public static native long PreKeySignalMessage_GetSignalMessage(long m);
  public static native int PreKeySignalMessage_GetSignedPreKeyId(long obj) throws Exception;
  public static native int PreKeySignalMessage_GetVersion(long obj) throws Exception;
  public static native long PreKeySignalMessage_New(int messageVersion, int registrationId, int preKeyId, int signedPreKeyId, long baseKey, long identityKey, long signalMessage) throws Exception;

  public static native void ProfileKeyCiphertext_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ProfileKeyCommitment_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ProfileKeyCredentialPresentation_CheckValidContents(byte[] presentationBytes) throws Exception;
  public static native byte[] ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(byte[] presentationBytes);
  public static native byte[] ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(byte[] presentationBytes);
  public static native byte[] ProfileKeyCredentialPresentation_GetUuidCiphertext(byte[] presentationBytes);

  public static native void ProfileKeyCredentialRequestContext_CheckValidContents(byte[] buffer) throws Exception;
  public static native byte[] ProfileKeyCredentialRequestContext_GetRequest(byte[] context);

  public static native void ProfileKeyCredentialRequest_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ProfileKey_CheckValidContents(byte[] buffer) throws Exception;
  public static native byte[] ProfileKey_DeriveAccessKey(byte[] profileKey);
  public static native byte[] ProfileKey_GetCommitment(byte[] profileKey, byte[] userId);
  public static native byte[] ProfileKey_GetProfileKeyVersion(byte[] profileKey, byte[] userId);

  public static native void ProtocolAddress_Destroy(long handle);
  public static native int ProtocolAddress_DeviceId(long obj);
  public static native String ProtocolAddress_Name(long obj);
  public static native long ProtocolAddress_New(String name, int deviceId);

  public static native void ReceiptCredentialPresentation_CheckValidContents(byte[] buffer) throws Exception;
  public static native long ReceiptCredentialPresentation_GetReceiptExpirationTime(byte[] presentation);
  public static native long ReceiptCredentialPresentation_GetReceiptLevel(byte[] presentation);
  public static native byte[] ReceiptCredentialPresentation_GetReceiptSerial(byte[] presentation);

  public static native void ReceiptCredentialRequestContext_CheckValidContents(byte[] buffer) throws Exception;
  public static native byte[] ReceiptCredentialRequestContext_GetRequest(byte[] requestContext);

  public static native void ReceiptCredentialRequest_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ReceiptCredentialResponse_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ReceiptCredential_CheckValidContents(byte[] buffer) throws Exception;
  public static native long ReceiptCredential_GetReceiptExpirationTime(byte[] receiptCredential);
  public static native long ReceiptCredential_GetReceiptLevel(byte[] receiptCredential);

  public static native void SanitizedMetadata_Destroy(long handle);
  public static native long SanitizedMetadata_GetDataLen(long sanitized);
  public static native long SanitizedMetadata_GetDataOffset(long sanitized);
  public static native byte[] SanitizedMetadata_GetMetadata(long sanitized);

  public static native boolean ScannableFingerprint_Compare(byte[] fprint1, byte[] fprint2) throws Exception;

  public static native Object SealedSender_MultiRecipientParseSentMessage(byte[] data);

  public static native long SealedSessionCipher_DecryptToUsmc(byte[] ctext, IdentityKeyStore identityStore) throws Exception;
  public static native byte[] SealedSessionCipher_Encrypt(long destination, long content, IdentityKeyStore identityKeyStore) throws Exception;
  public static native byte[] SealedSessionCipher_MultiRecipientEncrypt(long[] recipients, long[] recipientSessions, byte[] excludedRecipients, long content, IdentityKeyStore identityKeyStore) throws Exception;
  public static native byte[] SealedSessionCipher_MultiRecipientMessageForSingleRecipient(byte[] encodedMultiRecipientMessage) throws Exception;

  public static native void SearchResult_Destroy(long handle);
  public static native byte[] SearchResult_GetAccountData(long res);
  public static native byte[] SearchResult_GetAciForE164(long res);
  public static native byte[] SearchResult_GetAciForUsernameHash(long res);
  public static native long SearchResult_GetAciIdentityKey(long res);
  public static native long SearchResult_GetTimestamp(long res);

  public static native long SenderCertificate_Deserialize(byte[] data) throws Exception;
  public static native void SenderCertificate_Destroy(long handle);
  public static native byte[] SenderCertificate_GetCertificate(long obj) throws Exception;
  public static native int SenderCertificate_GetDeviceId(long obj) throws Exception;
  public static native long SenderCertificate_GetExpiration(long obj) throws Exception;
  public static native long SenderCertificate_GetKey(long obj) throws Exception;
  public static native String SenderCertificate_GetSenderE164(long obj) throws Exception;
  public static native String SenderCertificate_GetSenderUuid(long obj) throws Exception;
  public static native byte[] SenderCertificate_GetSerialized(long obj) throws Exception;
  public static native long SenderCertificate_GetServerCertificate(long cert) throws Exception;
  public static native byte[] SenderCertificate_GetSignature(long obj) throws Exception;
  public static native long SenderCertificate_New(String senderUuid, String senderE164, int senderDeviceId, long senderKey, long expiration, long signerCert, long signerKey) throws Exception;
  public static native boolean SenderCertificate_Validate(long cert, long key, long time) throws Exception;

  public static native long SenderKeyDistributionMessage_Deserialize(byte[] data) throws Exception;
  public static native void SenderKeyDistributionMessage_Destroy(long handle);
  public static native int SenderKeyDistributionMessage_GetChainId(long obj) throws Exception;
  public static native byte[] SenderKeyDistributionMessage_GetChainKey(long obj) throws Exception;
  public static native UUID SenderKeyDistributionMessage_GetDistributionId(long obj) throws Exception;
  public static native int SenderKeyDistributionMessage_GetIteration(long obj) throws Exception;
  public static native byte[] SenderKeyDistributionMessage_GetSerialized(long obj) throws Exception;
  public static native long SenderKeyDistributionMessage_GetSignatureKey(long m) throws Exception;
  public static native long SenderKeyDistributionMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] chainkey, long pk) throws Exception;

  public static native long SenderKeyMessage_Deserialize(byte[] data) throws Exception;
  public static native void SenderKeyMessage_Destroy(long handle);
  public static native int SenderKeyMessage_GetChainId(long obj) throws Exception;
  public static native byte[] SenderKeyMessage_GetCipherText(long obj) throws Exception;
  public static native UUID SenderKeyMessage_GetDistributionId(long obj) throws Exception;
  public static native int SenderKeyMessage_GetIteration(long obj) throws Exception;
  public static native byte[] SenderKeyMessage_GetSerialized(long obj) throws Exception;
  public static native long SenderKeyMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] ciphertext, long pk) throws Exception;
  public static native boolean SenderKeyMessage_VerifySignature(long skm, long pubkey) throws Exception;

  public static native long SenderKeyRecord_Deserialize(byte[] data) throws Exception;
  public static native void SenderKeyRecord_Destroy(long handle);
  public static native byte[] SenderKeyRecord_GetSerialized(long obj) throws Exception;

  public static native long ServerCertificate_Deserialize(byte[] data) throws Exception;
  public static native void ServerCertificate_Destroy(long handle);
  public static native byte[] ServerCertificate_GetCertificate(long obj) throws Exception;
  public static native long ServerCertificate_GetKey(long obj) throws Exception;
  public static native int ServerCertificate_GetKeyId(long obj) throws Exception;
  public static native byte[] ServerCertificate_GetSerialized(long obj) throws Exception;
  public static native byte[] ServerCertificate_GetSignature(long obj) throws Exception;
  public static native long ServerCertificate_New(int keyId, long serverKey, long trustRoot) throws Exception;

  public static native void ServerMessageAck_Destroy(long handle);
  public static native void ServerMessageAck_Send(long ack) throws Exception;

  public static native byte[] ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(long serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] authCredentialWithPniBytes);
  public static native byte[] ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(long serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] profileKeyCredential);
  public static native byte[] ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(long serverPublicParams, byte[] randomness, byte[] userId, byte[] profileKey);
  public static native byte[] ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(long serverPublicParams, byte[] randomness, byte[] receiptCredential);
  public static native byte[] ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(long serverPublicParams, byte[] randomness, byte[] receiptSerial);
  public static native long ServerPublicParams_Deserialize(byte[] buffer) throws Exception;
  public static native void ServerPublicParams_Destroy(long handle);
  public static native byte[] ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(long params, byte[] aci, byte[] pni, long redemptionTime, byte[] authCredentialWithPniResponseBytes) throws Exception;
  public static native byte[] ServerPublicParams_ReceiveExpiringProfileKeyCredential(long serverPublicParams, byte[] requestContext, byte[] response, long currentTimeInSeconds) throws Exception;
  public static native byte[] ServerPublicParams_ReceiveReceiptCredential(long serverPublicParams, byte[] requestContext, byte[] response) throws Exception;
  public static native byte[] ServerPublicParams_Serialize(long handle);
  public static native void ServerPublicParams_VerifySignature(long serverPublicParams, byte[] message, byte[] notarySignature) throws Exception;

  public static native long ServerSecretParams_Deserialize(byte[] buffer) throws Exception;
  public static native void ServerSecretParams_Destroy(long handle);
  public static native long ServerSecretParams_GenerateDeterministic(byte[] randomness);
  public static native long ServerSecretParams_GetPublicParams(long params);
  public static native byte[] ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(long serverSecretParams, byte[] randomness, byte[] aci, byte[] pni, long redemptionTime);
  public static native byte[] ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(long serverSecretParams, byte[] randomness, byte[] request, byte[] userId, byte[] commitment, long expirationInSeconds) throws Exception;
  public static native byte[] ServerSecretParams_IssueReceiptCredentialDeterministic(long serverSecretParams, byte[] randomness, byte[] request, long receiptExpirationTime, long receiptLevel);
  public static native byte[] ServerSecretParams_Serialize(long handle);
  public static native byte[] ServerSecretParams_SignDeterministic(long params, byte[] randomness, byte[] message);
  public static native void ServerSecretParams_VerifyAuthCredentialPresentation(long serverSecretParams, byte[] groupPublicParams, byte[] presentationBytes, long currentTimeInSeconds) throws Exception;
  public static native void ServerSecretParams_VerifyProfileKeyCredentialPresentation(long serverSecretParams, byte[] groupPublicParams, byte[] presentationBytes, long currentTimeInSeconds) throws Exception;
  public static native void ServerSecretParams_VerifyReceiptCredentialPresentation(long serverSecretParams, byte[] presentation) throws Exception;

  public static native byte[] ServiceId_ParseFromServiceIdBinary(byte[] input) throws Exception;
  public static native byte[] ServiceId_ParseFromServiceIdString(String input) throws Exception;
  public static native byte[] ServiceId_ServiceIdBinary(byte[] value);
  public static native String ServiceId_ServiceIdLog(byte[] value);
  public static native String ServiceId_ServiceIdString(byte[] value);

  public static native void SessionBuilder_ProcessPreKeyBundle(long bundle, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, long now) throws Exception;

  public static native byte[] SessionCipher_DecryptPreKeySignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, PreKeyStore prekeyStore, SignedPreKeyStore signedPrekeyStore, KyberPreKeyStore kyberPrekeyStore) throws Exception;
  public static native byte[] SessionCipher_DecryptSignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore) throws Exception;
  public static native CiphertextMessage SessionCipher_EncryptMessage(byte[] ptext, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, long now) throws Exception;

  public static native void SessionRecord_ArchiveCurrentState(long sessionRecord) throws Exception;
  public static native boolean SessionRecord_CurrentRatchetKeyMatches(long s, long key) throws Exception;
  public static native long SessionRecord_Deserialize(byte[] data) throws Exception;
  public static native void SessionRecord_Destroy(long handle);
  public static native byte[] SessionRecord_GetAliceBaseKey(long obj) throws Exception;
  public static native byte[] SessionRecord_GetLocalIdentityKeyPublic(long obj) throws Exception;
  public static native int SessionRecord_GetLocalRegistrationId(long obj) throws Exception;
  public static native byte[] SessionRecord_GetReceiverChainKeyValue(long sessionState, long key) throws Exception;
  public static native byte[] SessionRecord_GetRemoteIdentityKeyPublic(long obj) throws Exception;
  public static native int SessionRecord_GetRemoteRegistrationId(long obj) throws Exception;
  public static native byte[] SessionRecord_GetSenderChainKeyValue(long obj) throws Exception;
  public static native int SessionRecord_GetSessionVersion(long s) throws Exception;
  public static native boolean SessionRecord_HasUsableSenderChain(long s, long now) throws Exception;
  public static native long SessionRecord_InitializeAliceSession(long identityKeyPrivate, long identityKeyPublic, long basePrivate, long basePublic, long theirIdentityKey, long theirSignedPrekey, long theirRatchetKey) throws Exception;
  public static native long SessionRecord_InitializeBobSession(long identityKeyPrivate, long identityKeyPublic, long signedPrekeyPrivate, long signedPrekeyPublic, long ephPrivate, long ephPublic, long theirIdentityKey, long theirBaseKey) throws Exception;
  public static native long SessionRecord_NewFresh();
  public static native byte[] SessionRecord_Serialize(long obj) throws Exception;

  public static native void SgxClientState_CompleteHandshake(long cli, byte[] handshakeReceived) throws Exception;
  public static native void SgxClientState_Destroy(long handle);
  public static native byte[] SgxClientState_EstablishedRecv(long cli, byte[] receivedCiphertext) throws Exception;
  public static native byte[] SgxClientState_EstablishedSend(long cli, byte[] plaintextToSend) throws Exception;
  public static native byte[] SgxClientState_InitialRequest(long obj) throws Exception;

  public static native void SignalMedia_CheckAvailable();

  public static native long SignalMessage_Deserialize(byte[] data) throws Exception;
  public static native void SignalMessage_Destroy(long handle);
  public static native byte[] SignalMessage_GetBody(long obj) throws Exception;
  public static native int SignalMessage_GetCounter(long obj) throws Exception;
  public static native int SignalMessage_GetMessageVersion(long obj) throws Exception;
  public static native long SignalMessage_GetSenderRatchetKey(long m);
  public static native byte[] SignalMessage_GetSerialized(long obj) throws Exception;
  public static native long SignalMessage_New(int messageVersion, byte[] macKey, long senderRatchetKey, int counter, int previousCounter, byte[] ciphertext, long senderIdentityKey, long receiverIdentityKey) throws Exception;
  public static native boolean SignalMessage_VerifyMac(long msg, long senderIdentityKey, long receiverIdentityKey, byte[] macKey) throws Exception;

  public static native long SignedPreKeyRecord_Deserialize(byte[] data) throws Exception;
  public static native void SignedPreKeyRecord_Destroy(long handle);
  public static native int SignedPreKeyRecord_GetId(long obj) throws Exception;
  public static native long SignedPreKeyRecord_GetPrivateKey(long obj) throws Exception;
  public static native long SignedPreKeyRecord_GetPublicKey(long obj) throws Exception;
  public static native byte[] SignedPreKeyRecord_GetSerialized(long obj) throws Exception;
  public static native byte[] SignedPreKeyRecord_GetSignature(long obj) throws Exception;
  public static native long SignedPreKeyRecord_GetTimestamp(long obj) throws Exception;
  public static native long SignedPreKeyRecord_New(int id, long timestamp, long pubKey, long privKey, byte[] signature);

  public static native long Svr2Client_New(byte[] mrenclave, byte[] attestationMsg, long currentTimestamp) throws Exception;

  public static native void TokioAsyncContext_Destroy(long handle);
  public static native void TokioAsyncContext_cancel(long context, long rawCancellationId);
  public static native long TokioAsyncContext_new();

  public static native void UnauthenticatedChatConnection_Destroy(long handle);
  public static native CompletableFuture<Long> UnauthenticatedChatConnection_connect(long asyncRuntime, long connectionManager);
  public static native CompletableFuture UnauthenticatedChatConnection_disconnect(long asyncRuntime, long chat);
  public static native long UnauthenticatedChatConnection_info(long chat);
  public static native void UnauthenticatedChatConnection_init_listener(long chat, BridgeChatListener listener);
  public static native CompletableFuture<Object> UnauthenticatedChatConnection_send(long asyncRuntime, long chat, long httpRequest, int timeoutMillis);

  public static native long UnidentifiedSenderMessageContent_Deserialize(byte[] data) throws Exception;
  public static native void UnidentifiedSenderMessageContent_Destroy(long handle);
  public static native int UnidentifiedSenderMessageContent_GetContentHint(long m) throws Exception;
  public static native byte[] UnidentifiedSenderMessageContent_GetContents(long obj) throws Exception;
  public static native byte[] UnidentifiedSenderMessageContent_GetGroupId(long obj) throws Exception;
  public static native int UnidentifiedSenderMessageContent_GetMsgType(long m) throws Exception;
  public static native long UnidentifiedSenderMessageContent_GetSenderCert(long m) throws Exception;
  public static native byte[] UnidentifiedSenderMessageContent_GetSerialized(long obj) throws Exception;
  public static native long UnidentifiedSenderMessageContent_New(CiphertextMessage message, long sender, int contentHint, byte[] groupId) throws Exception;

  public static native byte[] UsernameLink_Create(String username, byte[] entropy) throws Exception;
  public static native String UsernameLink_DecryptUsername(byte[] entropy, byte[] encryptedUsername) throws Exception;

  public static native Object[] Username_CandidatesFrom(String nickname, int minLen, int maxLen) throws Exception;
  public static native byte[] Username_Hash(String username) throws Exception;
  public static native byte[] Username_HashFromParts(String nickname, String discriminator, int minLen, int maxLen) throws Exception;
  public static native byte[] Username_Proof(String username, byte[] randomness) throws Exception;
  public static native void Username_Verify(byte[] proof, byte[] hash) throws Exception;

  public static native void UuidCiphertext_CheckValidContents(byte[] buffer) throws Exception;

  public static native void ValidatingMac_Destroy(long handle);
  public static native int ValidatingMac_Finalize(long mac);
  public static native long ValidatingMac_Initialize(byte[] key, int chunkSize, byte[] digests);
  public static native int ValidatingMac_Update(long mac, byte[] bytes, int offset, int length);

  public static native void WebpSanitizer_Sanitize(InputStream input) throws Exception;

  public static native void initializeLibrary();
}
