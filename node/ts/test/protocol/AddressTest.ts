//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from '../../index.js';
import * as util from '../util.js';

import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as uuid from 'uuid';
import { Buffer } from 'node:buffer';

use(chaiAsPromised);
util.initLogger();

describe('ProtocolAddress', () => {
  it('can hold arbitrary name', () => {
    const addr = SignalClient.ProtocolAddress.new('name', 42);
    assert.deepEqual(addr.name(), 'name');
    assert.deepEqual(addr.deviceId(), 42);
  });
  it('can round-trip ServiceIds', () => {
    const newUuid = uuid.v4();
    const aci = SignalClient.Aci.fromUuid(newUuid);
    const pni = SignalClient.Pni.fromUuid(newUuid);

    const aciAddr = SignalClient.ProtocolAddress.new(aci, 1);
    const pniAddr = SignalClient.ProtocolAddress.new(pni, 1);
    assert.notEqual(aciAddr.toString(), pniAddr.toString());
    assert.isTrue(aciAddr.serviceId()?.isEqual(aci));
    assert.isTrue(pniAddr.serviceId()?.isEqual(pni));
  });

  it('rejects out-of-range device IDs', () => {
    assert.throws(
      () => SignalClient.ProtocolAddress.new('name', 128),
      'invalid: name.128'
    );
  });
});

describe('ServiceId', () => {
  const testingUuid = '8c78cd2a-16ff-427d-83dc-1a5e36ce713d';

  it('handles ACIs', () => {
    const aci = SignalClient.Aci.fromUuid(testingUuid);
    assert.instanceOf(aci, SignalClient.Aci);
    assert.isTrue(
      aci.isEqual(SignalClient.Aci.fromUuidBytes(uuid.parse(testingUuid)))
    );
    assert.isFalse(aci.isEqual(SignalClient.Pni.fromUuid(testingUuid)));

    assert.deepEqual(testingUuid, aci.getRawUuid());
    assert.deepEqual(uuid.parse(testingUuid), aci.getRawUuidBytes());
    assert.deepEqual(testingUuid, aci.getServiceIdString());
    assert.deepEqual(uuid.parse(testingUuid), aci.getServiceIdBinary());
    assert.deepEqual(`<ACI:${testingUuid}>`, `${aci}`);

    {
      const aciServiceId = SignalClient.ServiceId.parseFromServiceIdString(
        aci.getServiceIdString()
      );
      assert.instanceOf(aciServiceId, SignalClient.Aci);
      assert.deepEqual(aci, aciServiceId);

      const _: SignalClient.Aci = SignalClient.Aci.parseFromServiceIdString(
        aci.getServiceIdString()
      );
    }

    {
      const aciServiceId = SignalClient.ServiceId.parseFromServiceIdBinary(
        aci.getServiceIdBinary()
      );
      assert.instanceOf(aciServiceId, SignalClient.Aci);
      assert.deepEqual(aci, aciServiceId);

      const _: SignalClient.Aci = SignalClient.Aci.parseFromServiceIdBinary(
        aci.getServiceIdBinary()
      );
    }
  });
  it('handles PNIs', () => {
    const pni = SignalClient.Pni.fromUuid(testingUuid);
    assert.instanceOf(pni, SignalClient.Pni);
    assert.isTrue(
      pni.isEqual(SignalClient.Pni.fromUuidBytes(uuid.parse(testingUuid)))
    );
    assert.isFalse(pni.isEqual(SignalClient.Aci.fromUuid(testingUuid)));

    assert.deepEqual(testingUuid, pni.getRawUuid());
    assert.deepEqual(uuid.parse(testingUuid), pni.getRawUuidBytes());
    assert.deepEqual(`PNI:${testingUuid}`, pni.getServiceIdString());
    assert.deepEqual(
      Buffer.concat([Buffer.of(0x01), pni.getRawUuidBytes()]),
      pni.getServiceIdBinary()
    );
    assert.deepEqual(`<PNI:${testingUuid}>`, `${pni}`);

    {
      const pniServiceId = SignalClient.ServiceId.parseFromServiceIdString(
        pni.getServiceIdString()
      );
      assert.instanceOf(pniServiceId, SignalClient.Pni);
      assert.deepEqual(pni, pniServiceId);

      const _: SignalClient.Pni = SignalClient.Pni.parseFromServiceIdString(
        pni.getServiceIdString()
      );
    }

    {
      const pniServiceId = SignalClient.ServiceId.parseFromServiceIdBinary(
        pni.getServiceIdBinary()
      );
      assert.instanceOf(pniServiceId, SignalClient.Pni);
      assert.deepEqual(pni, pniServiceId);

      const _: SignalClient.Pni = SignalClient.Pni.parseFromServiceIdBinary(
        pni.getServiceIdBinary()
      );
    }
  });
  it('accepts the null UUID', () => {
    SignalClient.ServiceId.parseFromServiceIdString(uuid.NIL);
  });
  it('rejects invalid values', () => {
    assert.throws(() =>
      SignalClient.ServiceId.parseFromServiceIdBinary(Buffer.of())
    );
    assert.throws(() => SignalClient.ServiceId.parseFromServiceIdString(''));
  });
  it('follows the standard ordering', () => {
    const original = [
      SignalClient.Aci.fromUuid(uuid.NIL),
      SignalClient.Aci.fromUuid(testingUuid),
      SignalClient.Pni.fromUuid(uuid.NIL),
      SignalClient.Pni.fromUuid(testingUuid),
    ];
    const ids = util.shuffled(original);
    ids.sort(SignalClient.ServiceId.comparator);
    assert.deepEqual(ids, original);
  });
});
