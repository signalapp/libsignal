//
// Copyright (C) 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.client.internal;

import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

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
  }

  private Native() {}

  public static native byte[] HKDF_DeriveSecrets(int version, byte[] inputKeyMaterial,
                                                  byte[] salt, byte[] info, int outputLength);

  public static native long ECPublicKey_Deserialize(byte[] data, int offset);
  public static native byte[] ECPublicKey_Serialize(long handle);
  public static native byte[] ECPublicKey_GetPublicKeyBytes(long handle);
  public static native int ECPublicKey_Compare(long handle1, long handle2);
  public static native boolean ECPublicKey_Verify(long handle, byte[] message, byte[] signature);
  public static native void ECPublicKey_Destroy(long handle);

  public static native long ECPrivateKey_Generate();
  public static native long ECPrivateKey_Deserialize(byte[] data);
  public static native byte[] ECPrivateKey_Serialize(long handle);
  public static native byte[] ECPrivateKey_Sign(long handle, byte[] message);
  public static native byte[] ECPrivateKey_Agree(long handle, long pubkey_handle);
  public static native long ECPrivateKey_GetPublicKey(long handle);
  public static native void ECPrivateKey_Destroy(long handle);

  public static native byte[] IdentityKeyPair_Serialize(long pubHandle, long privHandle);

  public static native long NumericFingerprintGenerator_New(int iterations, int version, byte[] localIdentifier, byte[] localKey, byte[] remoteIdentifier, byte[] remoteKey);
  public static native String NumericFingerprintGenerator_GetDisplayString(long handle);
  public static native byte[] NumericFingerprintGenerator_GetScannableEncoding(long handle);
  public static native void NumericFingerprintGenerator_Destroy(long handle);
  public static native String DisplayableFingerprint_Format(byte[] localFingerprint, byte[] remoteFingerprint);
  public static native boolean ScannableFingerprint_Compare(byte[] ourFingerprint, byte[] scannedFingerprint);

  public static native long ProtocolAddress_New(String name, int device_id);
  public static native long ProtocolAddress_Destroy(long handle);
  public static native String ProtocolAddress_Name(long handle);
  public static native int ProtocolAddress_DeviceId(long handle);

  public static native long SignedPreKeyRecord_New(int id, long timestamp, long pubKeyHandle, long privKeyHandle, byte[] signature);
  public static native long SignedPreKeyRecord_Deserialize(byte[] serialized);
  public static native void SignedPreKeyRecord_Destroy(long handle);
  public static native int SignedPreKeyRecord_GetId(long handle);
  public static native long SignedPreKeyRecord_GetTimestamp(long handle);
  public static native long SignedPreKeyRecord_GetPublicKey(long handle);
  public static native long SignedPreKeyRecord_GetPrivateKey(long handle);
  public static native byte[] SignedPreKeyRecord_GetSignature(long handle);
  public static native byte[] SignedPreKeyRecord_GetSerialized(long handle);

  public static native byte[] SessionState_InitializeAliceSession(long identityKeyPrivateHandle,
                                                                  long identityKeyPublicHandle,
                                                                  long baseKeyPrivateHandle,
                                                                  long baseKeyPublicKeyHandle,
                                                                  long theirIdentityKeyPublicHandle,
                                                                  long theirSignedPreKeyPublicHandle,
                                                                  long theirRatchetKeyPublicHandle);

  public static native byte[] SessionState_InitializeBobSession(long identityKeyPrivateHandle,
                                                                long identityKeyPublicHandle,
                                                                long signedPreKeyPrivateHandle,
                                                                long signedPreKeyPublicKeyHandle,
                                                                long ephemeralKeyPrivateHandle,
                                                                long ephemeralKeyPublicHandle,
                                                                long theirIdentityKeyPublicHandle,
                                                                long theirBaseKeyPublicHandle);

  public static native long PreKeyBundle_New(int registrationId, int deviceId, int preKeyId, long preKeyPublicHandle,
                                             int signedPreKeyId, long signedPreKeyPublicHandle, byte[] signedPreKeySignature, long identityKeyHandle);
  public static native void PreKeyBundle_Destroy(long handle);
  public static native int PreKeyBundle_GetRegistrationId(long handle);
  public static native int PreKeyBundle_GetDeviceId(long handle);
  public static native int PreKeyBundle_GetPreKeyId(long handle);
  public static native int PreKeyBundle_GetSignedPreKeyId(long handle);
  public static native long PreKeyBundle_GetPreKeyPublic(long handle);
  public static native long PreKeyBundle_GetSignedPreKeyPublic(long handle);
  public static native byte[] PreKeyBundle_GetSignedPreKeySignature(long handle);
  public static native long PreKeyBundle_GetIdentityKey(long handle);

  public static native long PreKeyRecord_New(int id, long pubKeyHandle, long privKeyHandle);
  public static native long PreKeyRecord_Deserialize(byte[] serialized);
  public static native void PreKeyRecord_Destroy(long handle);
  public static native int PreKeyRecord_GetId(long handle);
  public static native long PreKeyRecord_GetPublicKey(long handle);
  public static native long PreKeyRecord_GetPrivateKey(long handle);
  public static native byte[] PreKeyRecord_GetSerialized(long handle);

  public static native CiphertextMessage SessionCipher_EncryptMessage(byte[] message, long remoteAddressHandle, SessionStore sessionStore, IdentityKeyStore identityKeyStore);
  public static native byte[] SessionCipher_DecryptSignalMessage(long signalMessageHandle, long remoteAddressHandle, SessionStore sessionStore, IdentityKeyStore identityKeyStore);
  public static native byte[] SessionCipher_DecryptPreKeySignalMessage(long preKeySignalMessageHandle, long remoteAddressHandle, SessionStore sessionStore,
                                                                       IdentityKeyStore identityKeyStore, PreKeyStore preKeyStore, SignedPreKeyStore signedPreKeyStore);

  public static native void SessionBuilder_ProcessPreKeyBundle(long preKeyBundleHandle,
                                                               long remoteAddressHandle,
                                                               SessionStore sessionStore,
                                                               IdentityKeyStore identityKeyStore);

  public static native long GroupSessionBuilder_CreateSenderKeyDistributionMessage(long senderKeyNameHandle,
                                                                SenderKeyStore senderKeyStore);
  public static native void GroupSessionBuilder_ProcessSenderKeyDistributionMessage(long senderKeyNameHandle,
                                                                 long senderKeyDistributionMessageHandle,
                                                                 SenderKeyStore senderKeyStore);

  public static native byte[] GroupCipher_EncryptMessage(long senderKeyNameHandle, byte[] paddedPlaintext, SenderKeyStore senderKeyStore);
  public static native byte[] GroupCipher_DecryptMessage(long senderKeyNameHandle, byte[] ciphertext, SenderKeyStore senderKeyStore);

  public static native long SignalMessage_Deserialize(byte[] serialized);
  public static native long SignalMessage_New(int messageVersion,
                                              byte[] macKey,
                                              long senderRatchetKeyHandle,
                                              int counter,
                                              int previousCounter,
                                              byte[] ciphertext,
                                              long senderIdentityKeyHandle,
                                              long receiverIdentityKeyHandle);
  public static native void SignalMessage_Destroy(long handle);
  public static native byte[] SignalMessage_GetSenderRatchetKey(long handle);
  public static native int SignalMessage_GetMessageVersion(long handle);
  public static native int SignalMessage_GetCounter(long handle);
  public static native byte[] SignalMessage_GetBody(long handle);
  public static native byte[] SignalMessage_GetSerialized(long handle);
  public static native boolean SignalMessage_VerifyMac(long messageHandle, long senderIdentityKeyHandle, long receiverIdentityKeyHandle, byte[] macKey);

  public static native long PreKeySignalMessage_Deserialize(byte[] serialized);
  public static native long PreKeySignalMessage_New(int messageVersion,
                                                    int registrationId,
                                                    int preKeyId,
                                                    int signedPreKeyId,
                                                    long baseKeyHandle,
                                                    long identityKeyHandle,
                                                    long signalMessageHandle);

  public static native void PreKeySignalMessage_Destroy(long handle);
  public static native int PreKeySignalMessage_GetVersion(long handle);
  public static native int PreKeySignalMessage_GetRegistrationId(long handle);
  public static native int PreKeySignalMessage_GetPreKeyId(long handle);
  public static native int PreKeySignalMessage_GetSignedPreKeyId(long handle);
  public static native byte[] PreKeySignalMessage_GetBaseKey(long handle);
  public static native byte[] PreKeySignalMessage_GetIdentityKey(long handle);
  public static native byte[] PreKeySignalMessage_GetSignalMessage(long handle);
  public static native byte[] PreKeySignalMessage_GetSerialized(long handle);

  public static native long SenderKeyName_New(String groupid, String senderName, int senderDeviceId);
  public static native void SenderKeyName_Destroy(long handle);
  public static native String SenderKeyName_GetSenderName(long handle);
  public static native int SenderKeyName_GetSenderDeviceId(long handle);
  public static native String SenderKeyName_GetGroupId(long handle);

  public static native long SenderKeyRecord_New();
  public static native long SenderKeyRecord_Deserialize(byte[] serialized);
  public static native void SenderKeyRecord_Destroy(long handle);
  public static native byte[] SenderKeyRecord_GetSerialized(long handle);

  public static native long SenderKeyMessage_Deserialize(byte[] serialized);
  public static native long SenderKeyMessage_New(int keyId, int iteration, byte[] ciphertext, long pkHandle);
  public static native void SenderKeyMessage_Destroy(long handle);
  public static native int SenderKeyMessage_GetKeyId(long handle);
  public static native int SenderKeyMessage_GetIteration(long handle);
  public static native byte[] SenderKeyMessage_GetCipherText(long handle);
  public static native byte[] SenderKeyMessage_GetSerialized(long handle);
  public static native boolean SenderKeyMessage_VerifySignature(long handle, long pkHandle);

  public static native long SenderKeyDistributionMessage_Deserialize(byte[] data);
  public static native long SenderKeyDistributionMessage_New(int id, int iteration, byte[] chainkey, long pkHandle);
  public static native long SenderKeyDistributionMessage_Destroy(long handle);
  public static native int SenderKeyDistributionMessage_GetIteration(long handle);
  public static native int SenderKeyDistributionMessage_GetId(long handle);
  public static native byte[] SenderKeyDistributionMessage_GetChainKey(long handle);
  public static native byte[] SenderKeyDistributionMessage_GetSignatureKey(long handle);
  public static native byte[] SenderKeyDistributionMessage_GetSerialized(long handle);
}
