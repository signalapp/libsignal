package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMacException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SenderKeyMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.util.guava.Optional;

import org.signal.client.internal.Native;

import java.util.List;
import java.util.UUID;

public class SealedSessionCipher {

  private static final String TAG = SealedSessionCipher.class.getSimpleName();

  private final SignalProtocolStore signalProtocolStore;
  private final String              localE164Address;
  private final String              localUuidAddress;
  private final int                 localDeviceId;

  public SealedSessionCipher(SignalProtocolStore signalProtocolStore,
                             UUID localUuid,
                             String localE164Address,
                             int localDeviceId)
  {
    this.signalProtocolStore = signalProtocolStore;
    this.localUuidAddress    = localUuid.toString();
    this.localE164Address    = localE164Address;
    this.localDeviceId       = localDeviceId;
  }

  public byte[] encrypt(SignalProtocolAddress destinationAddress, SenderCertificate senderCertificate, byte[] paddedPlaintext)
      throws InvalidKeyException, UntrustedIdentityException
  {
    CiphertextMessage message = Native.SessionCipher_EncryptMessage(
      paddedPlaintext,
      destinationAddress.nativeHandle(),
      this.signalProtocolStore,
      this.signalProtocolStore,
      null);
    UnidentifiedSenderMessageContent content = new UnidentifiedSenderMessageContent(
      message,
      senderCertificate,
      UnidentifiedSenderMessageContent.CONTENT_HINT_DEFAULT,
      Optional.<byte[]>absent());
    return encrypt(destinationAddress, content);
  }

  public byte[] encrypt(SignalProtocolAddress destinationAddress, UnidentifiedSenderMessageContent content)
      throws InvalidKeyException, UntrustedIdentityException
  {
    return Native.SealedSessionCipher_Encrypt(
      destinationAddress.nativeHandle(),
      content.nativeHandle(),
      this.signalProtocolStore,
      null);
  }

  public byte[] multiRecipientEncrypt(List<SignalProtocolAddress> recipients, UnidentifiedSenderMessageContent content)
      throws InvalidKeyException, UntrustedIdentityException
  {
    long[] recipientHandles = new long[recipients.size()];
    int i = 0;
    for (SignalProtocolAddress nextRecipient : recipients) {
      recipientHandles[i] = nextRecipient.nativeHandle();
      i++;
    }
    return Native.SealedSessionCipher_MultiRecipientEncrypt(
      recipientHandles,
      content.nativeHandle(),
      this.signalProtocolStore,
      null);
  }

  // For testing only.
  static byte[] multiRecipientMessageForSingleRecipient(byte[] message) {
    return Native.SealedSessionCipher_MultiRecipientMessageForSingleRecipient(message);
  }

  public DecryptionResult decrypt(CertificateValidator validator, byte[] ciphertext, long timestamp)
      throws
      InvalidMetadataMessageException, InvalidMetadataVersionException,
      ProtocolInvalidMessageException, ProtocolInvalidKeyException,
      ProtocolNoSessionException, ProtocolLegacyMessageException,
      ProtocolInvalidVersionException, ProtocolDuplicateMessageException,
      ProtocolInvalidKeyIdException, ProtocolUntrustedIdentityException,
      SelfSendException
  {
    UnidentifiedSenderMessageContent content;
    try {
      content = new UnidentifiedSenderMessageContent(
        Native.SealedSessionCipher_DecryptToUsmc(ciphertext, this.signalProtocolStore, null));
      validator.validate(content.getSenderCertificate(), timestamp);
    } catch (Exception e) {
      throw new InvalidMetadataMessageException(e);
    }

    boolean isLocalE164 = localE164Address != null && localE164Address.equals(content.getSenderCertificate().getSenderE164().orNull());
    boolean isLocalUuid = localUuidAddress.equals(content.getSenderCertificate().getSenderUuid());

    if ((isLocalE164 || isLocalUuid) && content.getSenderCertificate().getSenderDeviceId() == localDeviceId) {
      throw new SelfSendException();
    }

    try {
      return new DecryptionResult(content.getSenderCertificate().getSenderUuid(),
                                  content.getSenderCertificate().getSenderE164(),
                                  content.getSenderCertificate().getSenderDeviceId(),
                                  decrypt(content));
    } catch (InvalidMessageException e) {
      throw new ProtocolInvalidMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (InvalidKeyException e) {
      throw new ProtocolInvalidKeyException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (NoSessionException e) {
      throw new ProtocolNoSessionException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (LegacyMessageException e) {
      throw new ProtocolLegacyMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (InvalidVersionException e) {
      throw new ProtocolInvalidVersionException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (DuplicateMessageException e) {
      throw new ProtocolDuplicateMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (InvalidKeyIdException e) {
      throw new ProtocolInvalidKeyIdException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    } catch (UntrustedIdentityException e) {
      throw new ProtocolUntrustedIdentityException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId(), content.getContentHint(), content.getGroupId());
    }
  }

  public int getSessionVersion(SignalProtocolAddress remoteAddress) {
    return new SessionCipher(signalProtocolStore, remoteAddress).getSessionVersion();
  }

  public int getRemoteRegistrationId(SignalProtocolAddress remoteAddress) {
    return new SessionCipher(signalProtocolStore, remoteAddress).getRemoteRegistrationId();
  }

  private byte[] decrypt(UnidentifiedSenderMessageContent message)
      throws InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, UntrustedIdentityException, LegacyMessageException, NoSessionException
  {
    SignalProtocolAddress sender = new SignalProtocolAddress(message.getSenderCertificate().getSenderUuid(), message.getSenderCertificate().getSenderDeviceId());

    switch (message.getType()) {
      case CiphertextMessage.WHISPER_TYPE: return new SessionCipher(signalProtocolStore, sender).decrypt(new SignalMessage(message.getContent()));
      case CiphertextMessage.PREKEY_TYPE:  return new SessionCipher(signalProtocolStore, sender).decrypt(new PreKeySignalMessage(message.getContent()));
      case CiphertextMessage.SENDERKEY_TYPE:  return new GroupCipher(signalProtocolStore, sender).decrypt(message.getContent());
      default:                             throw new InvalidMessageException("Unknown type: " + message.getType());
    }
  }

  public static class DecryptionResult {
    private final String           senderUuid;
    private final Optional<String> senderE164;
    private final int              deviceId;
    private final byte[]           paddedMessage;

    private DecryptionResult(String senderUuid, Optional<String> senderE164, int deviceId, byte[] paddedMessage) {
      this.senderUuid    = senderUuid;
      this.senderE164    = senderE164;
      this.deviceId      = deviceId;
      this.paddedMessage = paddedMessage;
    }

    public String getSenderUuid() {
      return senderUuid;
    }

    public Optional<String> getSenderE164() {
      return senderE164;
    }

    public int getDeviceId() {
      return deviceId;
    }

    public byte[] getPaddedMessage() {
      return paddedMessage;
    }
  }
}
