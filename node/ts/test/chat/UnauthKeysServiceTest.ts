//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { TokioAsyncContext, UnauthKeysService } from '../../net.js';
import { connectUnauth } from './ServiceTestUtils.js';
import { Aci } from '../../Address.js';
import { GroupSendFullToken } from '../../zkgroup/index.js';
import { PublicKey } from '../../EcKeys.js';
import { ErrorCode, KEMPublicKey, LibSignalErrorBase } from '../../index.js';
import { fromBase64, toBase64 } from '../util.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthKeysService', () => {
  describe('getPreKeys', () => {
    const ACI = Aci.fromUuid('9d0652a3-dcc3-4d11-975f-74d61598733f');
    const DEVICE_ID = 2;
    const REGISTRATION_ID = 1234;
    const PRE_KEY_ID = 5;
    const SIGNED_PRE_KEY_ID = 7;
    const KYBER_PRE_KEY_ID = 9;
    const SECOND_DEVICE_ID = 3;
    const SECOND_REGISTRATION_ID = 5678;
    const SECOND_PRE_KEY_ID = 11;
    const SECOND_SIGNED_PRE_KEY_ID = 13;
    const SECOND_KYBER_PRE_KEY_ID = 15;

    // [0x11; 16]
    const TEST_ACCESS_KEY = fromBase64('EREREREREREREREREREREQ==');
    const IDENTITY_KEY = dummyEcPublicKey(0x12);

    const SIGNED_PRE_KEY_PUBLIC = dummyEcPublicKey(0x34);
    const SIGNED_PRE_KEY_SIGNATURE = repeatedBytes(0x56, 64);
    const KYBER_PRE_KEY_PUBLIC = dummyKemPublicKey(0x78);
    const KYBER_PRE_KEY_SIGNATURE = repeatedBytes(0x9a, 64);
    const PRE_KEY_PUBLIC = dummyEcPublicKey(0x43);

    const SECOND_PRE_KEY_PUBLIC = dummyEcPublicKey(0xd4);
    const SECOND_SIGNED_PRE_KEY_PUBLIC = dummyEcPublicKey(0x21);
    const SECOND_SIGNED_PRE_KEY_SIGNATURE = repeatedBytes(0x32, 64);
    const SECOND_KYBER_PRE_KEY_PUBLIC = dummyKemPublicKey(0x64);
    const SECOND_KYBER_PRE_KEY_SIGNATURE = repeatedBytes(0x64, 64);

    const TEST_GROUP_SEND_TOKEN = new GroupSendFullToken(
      fromBase64('ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA')
    );

    function repeatedBytes(
      fill: number,
      count: number
    ): Uint8Array<ArrayBuffer> {
      const out = new Uint8Array<ArrayBuffer>(new ArrayBuffer(count));
      for (let i = 0; i < count; i++) {
        out[i] = fill;
      }
      return out;
    }

    function bytePrefix(
      prefixByte: number,
      buf: Uint8Array<ArrayBuffer>
    ): Uint8Array<ArrayBuffer> {
      const out = new Uint8Array<ArrayBuffer>(new ArrayBuffer(1 + buf.length));
      out.set([prefixByte], 0);
      out.set(buf, 1);
      return out;
    }

    function dummyEcPublicKey(fill: number): PublicKey {
      return PublicKey.deserialize(bytePrefix(0x05, repeatedBytes(fill, 32)));
    }

    function dummyKemPublicKey(fill: number): KEMPublicKey {
      return KEMPublicKey.deserialize(
        // 1568 is kyber1024::Parameters::PUBLIC_KEY_LENGTH
        bytePrefix(0x08, repeatedBytes(fill, 1568))
      );
    }

    it('test single key with prekey', async () => {
      for (const { specifierString, specifier } of [
        { specifierString: '*', specifier: 'all' as const },
        { specifierString: `${DEVICE_ID}`, specifier: { deviceId: DEVICE_ID } },
      ]) {
        for (const { authHeaders, authValue } of [
          {
            authHeaders: new Map([
              ['unidentified-access-key', toBase64(TEST_ACCESS_KEY)],
            ]),
            authValue: { accessKey: TEST_ACCESS_KEY },
          },
          {
            authHeaders: new Map([
              ['group-send-token', toBase64(TEST_GROUP_SEND_TOKEN.serialize())],
            ]),
            authValue: TEST_GROUP_SEND_TOKEN,
          },
        ]) {
          const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
          const [service, fakeRemote] = connectUnauth<UnauthKeysService>(tokio);
          const responseFuture = service.getPreKeys({
            auth: authValue,
            target: ACI,
            device: specifier,
          });
          const request = await fakeRemote.assertReceiveIncomingRequest();
          expect(request.verb).to.eq('GET');
          expect(request.path).to.eq(
            `/v2/keys/${ACI.getRawUuid()}/${specifierString}`
          );
          expect(request.headers).to.deep.eq(authHeaders);
          expect(request.body.length).to.eq(0);
          fakeRemote.sendReplyTo(request, {
            status: 200,
            message: 'OK',
            headers: ['content-type: application/json'],
            body: new TextEncoder().encode(
              JSON.stringify({
                identityKey: toBase64(IDENTITY_KEY.serialize()),
                devices: [
                  {
                    deviceId: DEVICE_ID,
                    registrationId: REGISTRATION_ID,
                    preKey: {
                      keyId: PRE_KEY_ID,
                      publicKey: toBase64(PRE_KEY_PUBLIC.serialize()),
                    },
                    signedPreKey: {
                      keyId: SIGNED_PRE_KEY_ID,
                      publicKey: toBase64(SIGNED_PRE_KEY_PUBLIC.serialize()),
                      signature: toBase64(SIGNED_PRE_KEY_SIGNATURE),
                    },
                    pqPreKey: {
                      keyId: KYBER_PRE_KEY_ID,
                      publicKey: toBase64(KYBER_PRE_KEY_PUBLIC.serialize()),
                      signature: toBase64(KYBER_PRE_KEY_SIGNATURE),
                    },
                  },
                ],
              })
            ),
          });
          const { identityKey, preKeyBundles } = await responseFuture;
          expect(identityKey.serialize()).to.deep.eq(IDENTITY_KEY.serialize());
          expect(preKeyBundles.length).to.eq(1);
          const bundle = preKeyBundles[0];
          expect(bundle.kyberPreKeyId()).to.eq(KYBER_PRE_KEY_ID);
          expect(bundle.preKeyId()).to.eq(PRE_KEY_ID);
          expect(bundle.preKeyPublic()?.serialize()).to.deep.eq(
            PRE_KEY_PUBLIC.serialize()
          );
          expect(bundle.signedPreKeyPublic().serialize()).to.deep.eq(
            SIGNED_PRE_KEY_PUBLIC.serialize()
          );
          expect(bundle.signedPreKeySignature()).to.deep.eq(
            SIGNED_PRE_KEY_SIGNATURE
          );
          expect(bundle.kyberPreKeyPublic().serialize()).to.deep.eq(
            KYBER_PRE_KEY_PUBLIC.serialize()
          );
          expect(bundle.kyberPreKeySignature()).to.deep.eq(
            KYBER_PRE_KEY_SIGNATURE
          );
        }
      }
    });
    it('test single key with no prekey', async () => {
      for (const { specifierString, specifier } of [
        { specifierString: '*', specifier: 'all' as const },
        { specifierString: `${DEVICE_ID}`, specifier: { deviceId: DEVICE_ID } },
      ]) {
        for (const { authHeaders, authValue } of [
          {
            authHeaders: new Map([
              ['unidentified-access-key', toBase64(TEST_ACCESS_KEY)],
            ]),
            authValue: { accessKey: TEST_ACCESS_KEY },
          },
          {
            authHeaders: new Map([
              ['group-send-token', toBase64(TEST_GROUP_SEND_TOKEN.serialize())],
            ]),
            authValue: TEST_GROUP_SEND_TOKEN,
          },
        ]) {
          const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
          const [service, fakeRemote] = connectUnauth<UnauthKeysService>(tokio);
          const responseFuture = service.getPreKeys({
            auth: authValue,
            target: ACI,
            device: specifier,
          });
          const request = await fakeRemote.assertReceiveIncomingRequest();
          expect(request.verb).to.eq('GET');
          expect(request.path).to.eq(
            `/v2/keys/${ACI.getRawUuid()}/${specifierString}`
          );
          expect(request.headers).to.deep.eq(authHeaders);
          expect(request.body.length).to.eq(0);
          fakeRemote.sendReplyTo(request, {
            status: 200,
            message: 'OK',
            headers: ['content-type: application/json'],
            body: new TextEncoder().encode(
              JSON.stringify({
                identityKey: toBase64(IDENTITY_KEY.serialize()),
                devices: [
                  {
                    deviceId: DEVICE_ID,
                    registrationId: REGISTRATION_ID,
                    signedPreKey: {
                      keyId: SIGNED_PRE_KEY_ID,
                      publicKey: toBase64(SIGNED_PRE_KEY_PUBLIC.serialize()),
                      signature: toBase64(SIGNED_PRE_KEY_SIGNATURE),
                    },
                    pqPreKey: {
                      keyId: KYBER_PRE_KEY_ID,
                      publicKey: toBase64(KYBER_PRE_KEY_PUBLIC.serialize()),
                      signature: toBase64(KYBER_PRE_KEY_SIGNATURE),
                    },
                  },
                ],
              })
            ),
          });
          const { identityKey, preKeyBundles } = await responseFuture;
          expect(identityKey.serialize()).to.deep.eq(IDENTITY_KEY.serialize());
          expect(preKeyBundles.length).to.eq(1);
          const bundle = preKeyBundles[0];
          expect(bundle.kyberPreKeyId()).to.eq(KYBER_PRE_KEY_ID);
          expect(bundle.preKeyId()).to.eq(null);
          expect(bundle.preKeyPublic()).to.eq(null);
          expect(bundle.signedPreKeyPublic().serialize()).to.deep.eq(
            SIGNED_PRE_KEY_PUBLIC.serialize()
          );
          expect(bundle.signedPreKeySignature()).to.deep.eq(
            SIGNED_PRE_KEY_SIGNATURE
          );
          expect(bundle.kyberPreKeyPublic().serialize()).to.deep.eq(
            KYBER_PRE_KEY_PUBLIC.serialize()
          );
          expect(bundle.kyberPreKeySignature()).to.deep.eq(
            KYBER_PRE_KEY_SIGNATURE
          );
        }
      }
    });
    it('test all keys', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [service, fakeRemote] = connectUnauth<UnauthKeysService>(tokio);
      const responseFuture = service.getPreKeys({
        auth: { accessKey: TEST_ACCESS_KEY },
        target: ACI,
        device: 'all',
      });
      const request = await fakeRemote.assertReceiveIncomingRequest();
      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(`/v2/keys/${ACI.getRawUuid()}/*`);
      expect(request.headers).to.deep.eq(
        new Map([['unidentified-access-key', toBase64(TEST_ACCESS_KEY)]])
      );
      expect(request.body.length).to.eq(0);
      fakeRemote.sendReplyTo(request, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: new TextEncoder().encode(
          JSON.stringify({
            identityKey: toBase64(IDENTITY_KEY.serialize()),
            devices: [
              {
                deviceId: DEVICE_ID,
                registrationId: REGISTRATION_ID,
                signedPreKey: {
                  keyId: SIGNED_PRE_KEY_ID,
                  publicKey: toBase64(SIGNED_PRE_KEY_PUBLIC.serialize()),
                  signature: toBase64(SIGNED_PRE_KEY_SIGNATURE),
                },
                preKey: {
                  keyId: PRE_KEY_ID,
                  publicKey: toBase64(PRE_KEY_PUBLIC.serialize()),
                },
                pqPreKey: {
                  keyId: KYBER_PRE_KEY_ID,
                  publicKey: toBase64(KYBER_PRE_KEY_PUBLIC.serialize()),
                  signature: toBase64(KYBER_PRE_KEY_SIGNATURE),
                },
              },
              {
                deviceId: SECOND_DEVICE_ID,
                registrationId: SECOND_REGISTRATION_ID,
                signedPreKey: {
                  keyId: SECOND_SIGNED_PRE_KEY_ID,
                  publicKey: toBase64(SECOND_SIGNED_PRE_KEY_PUBLIC.serialize()),
                  signature: toBase64(SECOND_SIGNED_PRE_KEY_SIGNATURE),
                },
                preKey: {
                  keyId: SECOND_PRE_KEY_ID,
                  publicKey: toBase64(SECOND_PRE_KEY_PUBLIC.serialize()),
                },
                pqPreKey: {
                  keyId: SECOND_KYBER_PRE_KEY_ID,
                  publicKey: toBase64(SECOND_KYBER_PRE_KEY_PUBLIC.serialize()),
                  signature: toBase64(SECOND_KYBER_PRE_KEY_SIGNATURE),
                },
              },
            ],
          })
        ),
      });
      const { identityKey, preKeyBundles } = await responseFuture;
      expect(identityKey.serialize()).to.deep.eq(IDENTITY_KEY.serialize());
      expect(preKeyBundles.length).to.eq(2);
      expect(preKeyBundles[0].kyberPreKeyId()).to.eq(KYBER_PRE_KEY_ID);
      expect(preKeyBundles[0].preKeyId()).to.eq(PRE_KEY_ID);
      expect(preKeyBundles[0].preKeyPublic()?.serialize()).to.deep.eq(
        PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[0].signedPreKeyPublic().serialize()).to.deep.eq(
        SIGNED_PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[0].signedPreKeySignature()).to.deep.eq(
        SIGNED_PRE_KEY_SIGNATURE
      );
      expect(preKeyBundles[0].kyberPreKeyPublic().serialize()).to.deep.eq(
        KYBER_PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[0].kyberPreKeySignature()).to.deep.eq(
        KYBER_PRE_KEY_SIGNATURE
      );
      expect(preKeyBundles[1].kyberPreKeyId()).to.eq(SECOND_KYBER_PRE_KEY_ID);
      expect(preKeyBundles[1].preKeyId()).to.eq(SECOND_PRE_KEY_ID);
      expect(preKeyBundles[1].preKeyPublic()?.serialize()).to.deep.eq(
        SECOND_PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[1].signedPreKeyPublic().serialize()).to.deep.eq(
        SECOND_SIGNED_PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[1].signedPreKeySignature()).to.deep.eq(
        SECOND_SIGNED_PRE_KEY_SIGNATURE
      );
      expect(preKeyBundles[1].kyberPreKeyPublic().serialize()).to.deep.eq(
        SECOND_KYBER_PRE_KEY_PUBLIC.serialize()
      );
      expect(preKeyBundles[1].kyberPreKeySignature()).to.deep.eq(
        SECOND_KYBER_PRE_KEY_SIGNATURE
      );
    });
    it('should properly handle unauthorized', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthKeysService>(tokio);
      const responseFuture = chat.getPreKeys({
        auth: TEST_GROUP_SEND_TOKEN,
        target: ACI,
        device: 'all',
      });
      const request = await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(request, {
        status: 401,
        message: 'Unauthorized',
      });
      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.RequestUnauthorized,
        });
    });
    it('should properly handle not found', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthKeysService>(tokio);
      const responseFuture = chat.getPreKeys({
        auth: TEST_GROUP_SEND_TOKEN,
        target: ACI,
        device: 'all',
      });
      const request = await fakeRemote.assertReceiveIncomingRequest();
      fakeRemote.sendReplyTo(request, {
        status: 404,
        message: 'Not Found',
      });
      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.ServiceIdNotFound,
        });
    });
  });
});
