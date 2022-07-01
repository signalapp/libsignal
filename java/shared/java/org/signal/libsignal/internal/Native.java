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
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.logging.Log;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.UUID;
import java.util.Map;

public final class Native {
  private static void copyToTempFileAndLoad(InputStream in, String extension) throws IOException {
    File tempFile = Files.createTempFile("resource", extension).toFile();
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

  /*
  If a .so and/or .dylib is embedded within this jar as a resource file, attempt
  to copy it to a temporary file and then load it. This allows the jar to be
  used even without a libsignal_jni shared library existing on the filesystem.
  */
  private static void loadLibrary() {
    try {
      String  osName    = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
      boolean isMacOs   = osName.startsWith("mac os");
      String  extension = isMacOs ? ".dylib" : ".so";

      try (InputStream in = Native.class.getResourceAsStream("/libsignal_jni" + extension)) {
        if (in != null) {
          copyToTempFileAndLoad(in, extension);
        } else {
          System.loadLibrary("signal_jni");
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static {
    loadLibrary();
    Logger_Initialize(SignalProtocolLogger.INFO, Log.class);
  }

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

  public static native void Aes256Ctr32_Destroy(long handle);
  public static native long Aes256Ctr32_New(byte[] key, byte[] nonce, int initialCtr);
  public static native void Aes256Ctr32_Process(long ctr, byte[] data, int offset, int length);

  public static native void Aes256GcmDecryption_Destroy(long handle);
  public static native long Aes256GcmDecryption_New(byte[] key, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmDecryption_Update(long gcm, byte[] data, int offset, int length);
  public static native boolean Aes256GcmDecryption_VerifyTag(long gcm, byte[] tag);

  public static native byte[] Aes256GcmEncryption_ComputeTag(long gcm);
  public static native void Aes256GcmEncryption_Destroy(long handle);
  public static native long Aes256GcmEncryption_New(byte[] key, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmEncryption_Update(long gcm, byte[] data, int offset, int length);

  public static native byte[] Aes256GcmSiv_Decrypt(long aesGcmSiv, byte[] ctext, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmSiv_Destroy(long handle);
  public static native byte[] Aes256GcmSiv_Encrypt(long aesGcmSivObj, byte[] ptext, byte[] nonce, byte[] associatedData);
  public static native long Aes256GcmSiv_New(byte[] key);

  public static native void AuthCredentialPresentation_CheckValidContents(byte[] presentationBytes);
  public static native byte[] AuthCredentialPresentation_GetPniCiphertext(byte[] presentationBytes);
  public static native long AuthCredentialPresentation_GetRedemptionTime(byte[] presentationBytes);
  public static native byte[] AuthCredentialPresentation_GetUuidCiphertext(byte[] presentationBytes);

  public static native void AuthCredentialResponse_CheckValidContents(byte[] buffer);

  public static native void AuthCredentialWithPniResponse_CheckValidContents(byte[] buffer);

  public static native void AuthCredentialWithPni_CheckValidContents(byte[] buffer);

  public static native void AuthCredential_CheckValidContents(byte[] buffer);

  public static native void Cds2ClientState_CompleteHandshake(long cli, byte[] handshakeReceived);
  public static native void Cds2ClientState_Destroy(long handle);
  public static native byte[] Cds2ClientState_EstablishedRecv(long cli, byte[] receivedCiphertext);
  public static native byte[] Cds2ClientState_EstablishedSend(long cli, byte[] plaintextToSend);
  public static native byte[] Cds2ClientState_InitialRequest(long obj);
  public static native long Cds2ClientState_New(byte[] mrenclave, byte[] attestationMsg, long currentTimestamp);

  public static native Map Cds2Metrics_extract(byte[] attestationMsg);

  public static native void CryptographicHash_Destroy(long handle);
  public static native byte[] CryptographicHash_Finalize(long hash);
  public static native long CryptographicHash_New(String algo);
  public static native void CryptographicHash_Update(long hash, byte[] input);
  public static native void CryptographicHash_UpdateWithOffset(long hash, byte[] input, int offset, int len);

  public static native void CryptographicMac_Destroy(long handle);
  public static native byte[] CryptographicMac_Finalize(long mac);
  public static native long CryptographicMac_New(String algo, byte[] key);
  public static native void CryptographicMac_Update(long mac, byte[] input);
  public static native void CryptographicMac_UpdateWithOffset(long mac, byte[] input, int offset, int len);

  public static native long DecryptionErrorMessage_Deserialize(byte[] data);
  public static native void DecryptionErrorMessage_Destroy(long handle);
  public static native long DecryptionErrorMessage_ExtractFromSerializedContent(byte[] bytes);
  public static native long DecryptionErrorMessage_ForOriginalMessage(byte[] originalBytes, int originalType, long originalTimestamp, int originalSenderDeviceId);
  public static native int DecryptionErrorMessage_GetDeviceId(long obj);
  public static native long DecryptionErrorMessage_GetRatchetKey(long m);
  public static native byte[] DecryptionErrorMessage_GetSerialized(long obj);
  public static native long DecryptionErrorMessage_GetTimestamp(long obj);

  public static native byte[] DeviceTransfer_GenerateCertificate(byte[] privateKey, String name, int daysToExpire);
  public static native byte[] DeviceTransfer_GeneratePrivateKey();

  public static native byte[] ECPrivateKey_Agree(long privateKey, long publicKey);
  public static native long ECPrivateKey_Deserialize(byte[] data);
  public static native void ECPrivateKey_Destroy(long handle);
  public static native long ECPrivateKey_Generate();
  public static native long ECPrivateKey_GetPublicKey(long k);
  public static native byte[] ECPrivateKey_Serialize(long obj);
  public static native byte[] ECPrivateKey_Sign(long key, byte[] message);

  public static native int ECPublicKey_Compare(long key1, long key2);
  public static native long ECPublicKey_Deserialize(byte[] data, int offset);
  public static native void ECPublicKey_Destroy(long handle);
  public static native byte[] ECPublicKey_GetPublicKeyBytes(long obj);
  public static native byte[] ECPublicKey_Serialize(long obj);
  public static native boolean ECPublicKey_Verify(long key, byte[] message, byte[] signature);

  public static native void ExpiringProfileKeyCredentialResponse_CheckValidContents(byte[] buffer);

  public static native void ExpiringProfileKeyCredential_CheckValidContents(byte[] buffer);
  public static native long ExpiringProfileKeyCredential_GetExpirationTime(byte[] credential);

  public static native byte[] GroupCipher_DecryptMessage(long sender, byte[] message, SenderKeyStore store, Object ctx);
  public static native CiphertextMessage GroupCipher_EncryptMessage(long sender, UUID distributionId, byte[] message, SenderKeyStore store, Object ctx);

  public static native void GroupMasterKey_CheckValidContents(byte[] buffer);

  public static native void GroupPublicParams_CheckValidContents(byte[] buffer);
  public static native byte[] GroupPublicParams_GetGroupIdentifier(byte[] groupPublicParams);

  public static native void GroupSecretParams_CheckValidContents(byte[] buffer);
  public static native byte[] GroupSecretParams_DecryptBlobWithPadding(byte[] params, byte[] ciphertext);
  public static native byte[] GroupSecretParams_DecryptProfileKey(byte[] params, byte[] profileKey, UUID uuid);
  public static native UUID GroupSecretParams_DecryptUuid(byte[] params, byte[] uuid);
  public static native byte[] GroupSecretParams_DeriveFromMasterKey(byte[] masterKey);
  public static native byte[] GroupSecretParams_EncryptBlobWithPaddingDeterministic(byte[] params, byte[] randomness, byte[] plaintext, int paddingLen);
  public static native byte[] GroupSecretParams_EncryptProfileKey(byte[] params, byte[] profileKey, UUID uuid);
  public static native byte[] GroupSecretParams_EncryptUuid(byte[] params, UUID uuid);
  public static native byte[] GroupSecretParams_GenerateDeterministic(byte[] randomness);
  public static native byte[] GroupSecretParams_GetMasterKey(byte[] params);
  public static native byte[] GroupSecretParams_GetPublicParams(byte[] params);

  public static native long GroupSessionBuilder_CreateSenderKeyDistributionMessage(long sender, UUID distributionId, SenderKeyStore store, Object ctx);
  public static native void GroupSessionBuilder_ProcessSenderKeyDistributionMessage(long sender, long senderKeyDistributionMessage, SenderKeyStore store, Object ctx);

  public static native byte[] HKDF_DeriveSecrets(int outputLength, byte[] ikm, byte[] label, byte[] salt);

  public static native void HsmEnclaveClient_CompleteHandshake(long cli, byte[] handshakeReceived);
  public static native void HsmEnclaveClient_Destroy(long handle);
  public static native byte[] HsmEnclaveClient_EstablishedRecv(long cli, byte[] receivedCiphertext);
  public static native byte[] HsmEnclaveClient_EstablishedSend(long cli, byte[] plaintextToSend);
  public static native byte[] HsmEnclaveClient_InitialRequest(long obj);
  public static native long HsmEnclaveClient_New(byte[] trustedPublicKey, byte[] trustedCodeHashes);

  public static native long[] IdentityKeyPair_Deserialize(byte[] data);
  public static native byte[] IdentityKeyPair_Serialize(long publicKey, long privateKey);
  public static native byte[] IdentityKeyPair_SignAlternateIdentity(long publicKey, long privateKey, long otherIdentity);

  public static native boolean IdentityKey_VerifyAlternateIdentity(long publicKey, long otherIdentity, byte[] signature);

  public static native void Logger_Initialize(int maxLevel, Class loggerClass);
  public static native void Logger_SetMaxLevel(int maxLevel);

  public static native void NumericFingerprintGenerator_Destroy(long handle);
  public static native String NumericFingerprintGenerator_GetDisplayString(long obj);
  public static native byte[] NumericFingerprintGenerator_GetScannableEncoding(long obj);
  public static native long NumericFingerprintGenerator_New(int iterations, int version, byte[] localIdentifier, byte[] localKey, byte[] remoteIdentifier, byte[] remoteKey);

  public static native long PlaintextContent_Deserialize(byte[] data);
  public static native byte[] PlaintextContent_DeserializeAndGetContent(byte[] bytes);
  public static native void PlaintextContent_Destroy(long handle);
  public static native long PlaintextContent_FromDecryptionErrorMessage(long m);
  public static native byte[] PlaintextContent_GetBody(long obj);
  public static native byte[] PlaintextContent_GetSerialized(long obj);

  public static native void PniCredentialPresentation_CheckValidContents(byte[] presentationBytes);
  public static native byte[] PniCredentialPresentation_GetAciCiphertext(byte[] presentationBytes);
  public static native byte[] PniCredentialPresentation_GetPniCiphertext(byte[] presentationBytes);
  public static native byte[] PniCredentialPresentation_GetProfileKeyCiphertext(byte[] presentationBytes);

  public static native void PniCredentialRequestContext_CheckValidContents(byte[] buffer);
  public static native byte[] PniCredentialRequestContext_GetRequest(byte[] context);

  public static native void PniCredentialResponse_CheckValidContents(byte[] buffer);

  public static native void PniCredential_CheckValidContents(byte[] buffer);

  public static native void PreKeyBundle_Destroy(long handle);
  public static native int PreKeyBundle_GetDeviceId(long obj);
  public static native long PreKeyBundle_GetIdentityKey(long p);
  public static native int PreKeyBundle_GetPreKeyId(long obj);
  public static native long PreKeyBundle_GetPreKeyPublic(long obj);
  public static native int PreKeyBundle_GetRegistrationId(long obj);
  public static native int PreKeyBundle_GetSignedPreKeyId(long obj);
  public static native long PreKeyBundle_GetSignedPreKeyPublic(long obj);
  public static native byte[] PreKeyBundle_GetSignedPreKeySignature(long obj);
  public static native long PreKeyBundle_New(int registrationId, int deviceId, int prekeyId, long prekey, int signedPrekeyId, long signedPrekey, byte[] signedPrekeySignature, long identityKey);

  public static native long PreKeyRecord_Deserialize(byte[] data);
  public static native void PreKeyRecord_Destroy(long handle);
  public static native int PreKeyRecord_GetId(long obj);
  public static native long PreKeyRecord_GetPrivateKey(long obj);
  public static native long PreKeyRecord_GetPublicKey(long obj);
  public static native byte[] PreKeyRecord_GetSerialized(long obj);
  public static native long PreKeyRecord_New(int id, long pubKey, long privKey);

  public static native long PreKeySignalMessage_Deserialize(byte[] data);
  public static native void PreKeySignalMessage_Destroy(long handle);
  public static native long PreKeySignalMessage_GetBaseKey(long m);
  public static native long PreKeySignalMessage_GetIdentityKey(long m);
  public static native int PreKeySignalMessage_GetPreKeyId(long obj);
  public static native int PreKeySignalMessage_GetRegistrationId(long obj);
  public static native byte[] PreKeySignalMessage_GetSerialized(long obj);
  public static native long PreKeySignalMessage_GetSignalMessage(long m);
  public static native int PreKeySignalMessage_GetSignedPreKeyId(long obj);
  public static native int PreKeySignalMessage_GetVersion(long obj);
  public static native long PreKeySignalMessage_New(int messageVersion, int registrationId, int preKeyId, int signedPreKeyId, long baseKey, long identityKey, long signalMessage);

  public static native void ProfileKeyCiphertext_CheckValidContents(byte[] buffer);

  public static native void ProfileKeyCommitment_CheckValidContents(byte[] buffer);

  public static native void ProfileKeyCredentialPresentation_CheckValidContents(byte[] presentationBytes);
  public static native byte[] ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(byte[] presentationBytes);
  public static native byte[] ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(byte[] presentationBytes);
  public static native byte[] ProfileKeyCredentialPresentation_GetUuidCiphertext(byte[] presentationBytes);

  public static native void ProfileKeyCredentialRequestContext_CheckValidContents(byte[] buffer);
  public static native byte[] ProfileKeyCredentialRequestContext_GetRequest(byte[] context);

  public static native void ProfileKeyCredentialRequest_CheckValidContents(byte[] buffer);

  public static native void ProfileKeyCredentialResponse_CheckValidContents(byte[] buffer);

  public static native void ProfileKeyCredential_CheckValidContents(byte[] buffer);

  public static native void ProfileKey_CheckValidContents(byte[] buffer);
  public static native byte[] ProfileKey_GetCommitment(byte[] profileKey, UUID uuid);
  public static native byte[] ProfileKey_GetProfileKeyVersion(byte[] profileKey, UUID uuid);

  public static native void ProtocolAddress_Destroy(long handle);
  public static native int ProtocolAddress_DeviceId(long obj);
  public static native String ProtocolAddress_Name(long obj);
  public static native long ProtocolAddress_New(String name, int deviceId);

  public static native void ReceiptCredentialPresentation_CheckValidContents(byte[] buffer);
  public static native long ReceiptCredentialPresentation_GetReceiptExpirationTime(byte[] presentation);
  public static native long ReceiptCredentialPresentation_GetReceiptLevel(byte[] presentation);
  public static native byte[] ReceiptCredentialPresentation_GetReceiptSerial(byte[] presentation);

  public static native void ReceiptCredentialRequestContext_CheckValidContents(byte[] buffer);
  public static native byte[] ReceiptCredentialRequestContext_GetRequest(byte[] requestContext);

  public static native void ReceiptCredentialRequest_CheckValidContents(byte[] buffer);

  public static native void ReceiptCredentialResponse_CheckValidContents(byte[] buffer);

  public static native void ReceiptCredential_CheckValidContents(byte[] buffer);
  public static native long ReceiptCredential_GetReceiptExpirationTime(byte[] receiptCredential);
  public static native long ReceiptCredential_GetReceiptLevel(byte[] receiptCredential);

  public static native boolean ScannableFingerprint_Compare(byte[] fprint1, byte[] fprint2);

  public static native long SealedSessionCipher_DecryptToUsmc(byte[] ctext, IdentityKeyStore identityStore, Object ctx);
  public static native byte[] SealedSessionCipher_Encrypt(long destination, long content, IdentityKeyStore identityKeyStore, Object ctx);
  public static native byte[] SealedSessionCipher_MultiRecipientEncrypt(long[] recipients, long[] recipientSessions, long content, IdentityKeyStore identityKeyStore, Object ctx);
  public static native byte[] SealedSessionCipher_MultiRecipientMessageForSingleRecipient(byte[] encodedMultiRecipientMessage);

  public static native long SenderCertificate_Deserialize(byte[] data);
  public static native void SenderCertificate_Destroy(long handle);
  public static native byte[] SenderCertificate_GetCertificate(long obj);
  public static native int SenderCertificate_GetDeviceId(long obj);
  public static native long SenderCertificate_GetExpiration(long obj);
  public static native long SenderCertificate_GetKey(long obj);
  public static native String SenderCertificate_GetSenderE164(long obj);
  public static native String SenderCertificate_GetSenderUuid(long obj);
  public static native byte[] SenderCertificate_GetSerialized(long obj);
  public static native long SenderCertificate_GetServerCertificate(long cert);
  public static native byte[] SenderCertificate_GetSignature(long obj);
  public static native long SenderCertificate_New(String senderUuid, String senderE164, int senderDeviceId, long senderKey, long expiration, long signerCert, long signerKey);
  public static native boolean SenderCertificate_Validate(long cert, long key, long time);

  public static native long SenderKeyDistributionMessage_Deserialize(byte[] data);
  public static native void SenderKeyDistributionMessage_Destroy(long handle);
  public static native int SenderKeyDistributionMessage_GetChainId(long obj);
  public static native byte[] SenderKeyDistributionMessage_GetChainKey(long obj);
  public static native UUID SenderKeyDistributionMessage_GetDistributionId(long obj);
  public static native int SenderKeyDistributionMessage_GetIteration(long obj);
  public static native byte[] SenderKeyDistributionMessage_GetSerialized(long obj);
  public static native long SenderKeyDistributionMessage_GetSignatureKey(long m);
  public static native long SenderKeyDistributionMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] chainkey, long pk);

  public static native long SenderKeyMessage_Deserialize(byte[] data);
  public static native void SenderKeyMessage_Destroy(long handle);
  public static native int SenderKeyMessage_GetChainId(long obj);
  public static native byte[] SenderKeyMessage_GetCipherText(long obj);
  public static native UUID SenderKeyMessage_GetDistributionId(long obj);
  public static native int SenderKeyMessage_GetIteration(long obj);
  public static native byte[] SenderKeyMessage_GetSerialized(long obj);
  public static native long SenderKeyMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] ciphertext, long pk);
  public static native boolean SenderKeyMessage_VerifySignature(long skm, long pubkey);

  public static native long SenderKeyRecord_Deserialize(byte[] data);
  public static native void SenderKeyRecord_Destroy(long handle);
  public static native byte[] SenderKeyRecord_GetSerialized(long obj);

  public static native long ServerCertificate_Deserialize(byte[] data);
  public static native void ServerCertificate_Destroy(long handle);
  public static native byte[] ServerCertificate_GetCertificate(long obj);
  public static native long ServerCertificate_GetKey(long obj);
  public static native int ServerCertificate_GetKeyId(long obj);
  public static native byte[] ServerCertificate_GetSerialized(long obj);
  public static native byte[] ServerCertificate_GetSignature(long obj);
  public static native long ServerCertificate_New(int keyId, long serverKey, long trustRoot);

  public static native void ServerPublicParams_CheckValidContents(byte[] buffer);
  public static native byte[] ServerPublicParams_CreateAuthCredentialPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] authCredential);
  public static native byte[] ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] authCredential);
  public static native byte[] ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] profileKeyCredential);
  public static native byte[] ServerPublicParams_CreatePniCredentialPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] pniCredential);
  public static native byte[] ServerPublicParams_CreatePniCredentialRequestContextDeterministic(byte[] serverPublicParams, byte[] randomness, UUID aci, UUID pni, byte[] profileKey);
  public static native byte[] ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] groupSecretParams, byte[] profileKeyCredential);
  public static native byte[] ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(byte[] serverPublicParams, byte[] randomness, UUID uuid, byte[] profileKey);
  public static native byte[] ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] receiptCredential);
  public static native byte[] ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(byte[] serverPublicParams, byte[] randomness, byte[] receiptSerial);
  public static native byte[] ServerPublicParams_ReceiveAuthCredential(byte[] params, UUID uuid, int redemptionTime, byte[] response);
  public static native byte[] ServerPublicParams_ReceiveAuthCredentialWithPni(byte[] params, UUID aci, UUID pni, long redemptionTime, byte[] response);
  public static native byte[] ServerPublicParams_ReceiveExpiringProfileKeyCredential(byte[] serverPublicParams, byte[] requestContext, byte[] response, long currentTimeInSeconds);
  public static native byte[] ServerPublicParams_ReceivePniCredential(byte[] serverPublicParams, byte[] requestContext, byte[] response);
  public static native byte[] ServerPublicParams_ReceiveProfileKeyCredential(byte[] serverPublicParams, byte[] requestContext, byte[] response);
  public static native byte[] ServerPublicParams_ReceiveReceiptCredential(byte[] serverPublicParams, byte[] requestContext, byte[] response);
  public static native void ServerPublicParams_VerifySignature(byte[] serverPublicParams, byte[] message, byte[] notarySignature);

  public static native void ServerSecretParams_CheckValidContents(byte[] buffer);
  public static native byte[] ServerSecretParams_GenerateDeterministic(byte[] randomness);
  public static native byte[] ServerSecretParams_GetPublicParams(byte[] params);
  public static native byte[] ServerSecretParams_IssueAuthCredentialDeterministic(byte[] serverSecretParams, byte[] randomness, UUID uuid, int redemptionTime);
  public static native byte[] ServerSecretParams_IssueAuthCredentialWithPniDeterministic(byte[] serverSecretParams, byte[] randomness, UUID aci, UUID pni, long redemptionTime);
  public static native byte[] ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(byte[] serverSecretParams, byte[] randomness, byte[] request, UUID uuid, byte[] commitment, long expirationInSeconds);
  public static native byte[] ServerSecretParams_IssuePniCredentialDeterministic(byte[] serverSecretParams, byte[] randomness, byte[] request, UUID aci, UUID pni, byte[] commitment);
  public static native byte[] ServerSecretParams_IssueProfileKeyCredentialDeterministic(byte[] serverSecretParams, byte[] randomness, byte[] request, UUID uuid, byte[] commitment);
  public static native byte[] ServerSecretParams_IssueReceiptCredentialDeterministic(byte[] serverSecretParams, byte[] randomness, byte[] request, long receiptExpirationTime, long receiptLevel);
  public static native byte[] ServerSecretParams_SignDeterministic(byte[] params, byte[] randomness, byte[] message);
  public static native void ServerSecretParams_VerifyAuthCredentialPresentation(byte[] serverSecretParams, byte[] groupPublicParams, byte[] presentationBytes, long currentTimeInSeconds);
  public static native void ServerSecretParams_VerifyPniCredentialPresentation(byte[] serverSecretParams, byte[] groupPublicParams, byte[] presentationBytes);
  public static native void ServerSecretParams_VerifyProfileKeyCredentialPresentation(byte[] serverSecretParams, byte[] groupPublicParams, byte[] presentationBytes, long currentTimeInSeconds);
  public static native void ServerSecretParams_VerifyReceiptCredentialPresentation(byte[] serverSecretParams, byte[] presentation);

  public static native void SessionBuilder_ProcessPreKeyBundle(long bundle, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);

  public static native byte[] SessionCipher_DecryptPreKeySignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, PreKeyStore prekeyStore, SignedPreKeyStore signedPrekeyStore, Object ctx);
  public static native byte[] SessionCipher_DecryptSignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);
  public static native CiphertextMessage SessionCipher_EncryptMessage(byte[] ptext, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);

  public static native void SessionRecord_ArchiveCurrentState(long sessionRecord);
  public static native boolean SessionRecord_CurrentRatchetKeyMatches(long s, long key);
  public static native long SessionRecord_Deserialize(byte[] data);
  public static native void SessionRecord_Destroy(long handle);
  public static native long SessionRecord_FromSingleSessionState(byte[] sessionState);
  public static native byte[] SessionRecord_GetAliceBaseKey(long obj);
  public static native byte[] SessionRecord_GetLocalIdentityKeyPublic(long obj);
  public static native int SessionRecord_GetLocalRegistrationId(long obj);
  public static native byte[] SessionRecord_GetReceiverChainKeyValue(long sessionState, long key);
  public static native byte[] SessionRecord_GetRemoteIdentityKeyPublic(long obj);
  public static native int SessionRecord_GetRemoteRegistrationId(long obj);
  public static native byte[] SessionRecord_GetSenderChainKeyValue(long obj);
  public static native int SessionRecord_GetSessionVersion(long s);
  public static native boolean SessionRecord_HasSenderChain(long obj);
  public static native long SessionRecord_InitializeAliceSession(long identityKeyPrivate, long identityKeyPublic, long basePrivate, long basePublic, long theirIdentityKey, long theirSignedPrekey, long theirRatchetKey);
  public static native long SessionRecord_InitializeBobSession(long identityKeyPrivate, long identityKeyPublic, long signedPrekeyPrivate, long signedPrekeyPublic, long ephPrivate, long ephPublic, long theirIdentityKey, long theirBaseKey);
  public static native long SessionRecord_NewFresh();
  public static native byte[] SessionRecord_Serialize(long obj);

  public static native long SignalMessage_Deserialize(byte[] data);
  public static native void SignalMessage_Destroy(long handle);
  public static native byte[] SignalMessage_GetBody(long obj);
  public static native int SignalMessage_GetCounter(long obj);
  public static native int SignalMessage_GetMessageVersion(long obj);
  public static native long SignalMessage_GetSenderRatchetKey(long m);
  public static native byte[] SignalMessage_GetSerialized(long obj);
  public static native long SignalMessage_New(int messageVersion, byte[] macKey, long senderRatchetKey, int counter, int previousCounter, byte[] ciphertext, long senderIdentityKey, long receiverIdentityKey);
  public static native boolean SignalMessage_VerifyMac(long msg, long senderIdentityKey, long receiverIdentityKey, byte[] macKey);

  public static native long SignedPreKeyRecord_Deserialize(byte[] data);
  public static native void SignedPreKeyRecord_Destroy(long handle);
  public static native int SignedPreKeyRecord_GetId(long obj);
  public static native long SignedPreKeyRecord_GetPrivateKey(long obj);
  public static native long SignedPreKeyRecord_GetPublicKey(long obj);
  public static native byte[] SignedPreKeyRecord_GetSerialized(long obj);
  public static native byte[] SignedPreKeyRecord_GetSignature(long obj);
  public static native long SignedPreKeyRecord_GetTimestamp(long obj);
  public static native long SignedPreKeyRecord_New(int id, long timestamp, long pubKey, long privKey, byte[] signature);

  public static native long UnidentifiedSenderMessageContent_Deserialize(byte[] data);
  public static native void UnidentifiedSenderMessageContent_Destroy(long handle);
  public static native int UnidentifiedSenderMessageContent_GetContentHint(long m);
  public static native byte[] UnidentifiedSenderMessageContent_GetContents(long obj);
  public static native byte[] UnidentifiedSenderMessageContent_GetGroupId(long obj);
  public static native int UnidentifiedSenderMessageContent_GetMsgType(long m);
  public static native long UnidentifiedSenderMessageContent_GetSenderCert(long m);
  public static native byte[] UnidentifiedSenderMessageContent_GetSerialized(long obj);
  public static native long UnidentifiedSenderMessageContent_New(CiphertextMessage message, long sender, int contentHint, byte[] groupId);

  public static native void UuidCiphertext_CheckValidContents(byte[] buffer);
}
