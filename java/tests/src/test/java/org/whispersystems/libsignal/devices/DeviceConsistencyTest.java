package org.whispersystems.libsignal.devices;

import junit.framework.TestCase;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.protocol.DeviceConsistencyMessage;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class DeviceConsistencyTest extends TestCase {

  public void testDeviceConsistency() throws InvalidMessageException {
    final IdentityKeyPair deviceOne   = KeyHelper.generateIdentityKeyPair();
    final IdentityKeyPair deviceTwo   = KeyHelper.generateIdentityKeyPair();
    final IdentityKeyPair deviceThree = KeyHelper.generateIdentityKeyPair();

    List<IdentityKey> keyList = new LinkedList<IdentityKey>() {{
      add(deviceOne.getPublicKey());
      add(deviceTwo.getPublicKey());
      add(deviceThree.getPublicKey());
    }};

    Collections.shuffle(keyList);
    DeviceConsistencyCommitment deviceOneCommitment = new DeviceConsistencyCommitment(1, keyList);

    Collections.shuffle(keyList);
    DeviceConsistencyCommitment deviceTwoCommitment = new DeviceConsistencyCommitment(1, keyList);

    Collections.shuffle(keyList);
    DeviceConsistencyCommitment deviceThreeCommitment = new DeviceConsistencyCommitment(1, keyList);

    assertTrue(Arrays.equals(deviceOneCommitment.toByteArray(), deviceTwoCommitment.toByteArray()));
    assertTrue(Arrays.equals(deviceTwoCommitment.toByteArray(), deviceThreeCommitment.toByteArray()));

    DeviceConsistencyMessage deviceOneMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceOne);
    DeviceConsistencyMessage deviceTwoMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceTwo);
    DeviceConsistencyMessage deviceThreeMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceThree);

    DeviceConsistencyMessage receivedDeviceOneMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceOneMessage.getSerialized(), deviceOne.getPublicKey());
    DeviceConsistencyMessage receivedDeviceTwoMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceTwoMessage.getSerialized(), deviceTwo.getPublicKey());
    DeviceConsistencyMessage receivedDeviceThreeMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceThreeMessage.getSerialized(), deviceThree.getPublicKey());

    assertTrue(Arrays.equals(deviceOneMessage.getSignature().getVrfOutput(), receivedDeviceOneMessage.getSignature().getVrfOutput()));
    assertTrue(Arrays.equals(deviceTwoMessage.getSignature().getVrfOutput(), receivedDeviceTwoMessage.getSignature().getVrfOutput()));
    assertTrue(Arrays.equals(deviceThreeMessage.getSignature().getVrfOutput(), receivedDeviceThreeMessage.getSignature().getVrfOutput()));

    String codeOne = generateCode(deviceOneCommitment, deviceOneMessage, receivedDeviceTwoMessage, receivedDeviceThreeMessage);
    String codeTwo = generateCode(deviceTwoCommitment, deviceTwoMessage, receivedDeviceThreeMessage, receivedDeviceOneMessage);
    String codeThree = generateCode(deviceThreeCommitment, deviceThreeMessage, receivedDeviceTwoMessage, receivedDeviceOneMessage);

    assertEquals(codeOne, codeTwo);
    assertEquals(codeTwo, codeThree);
  }

  private String generateCode(DeviceConsistencyCommitment commitment,
                              DeviceConsistencyMessage... messages)
  {
    List<DeviceConsistencySignature> signatures = new LinkedList<>();

    for (DeviceConsistencyMessage message : messages) {
      signatures.add(message.getSignature());
    }

    return DeviceConsistencyCodeGenerator.generateFor(commitment, signatures);
  }


}
