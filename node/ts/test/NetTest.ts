//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as util from './util';
import { Aci, Pni } from '../Address';
import * as Native from '../../Native';
import { ErrorCode, LibSignalErrorBase } from '../Errors';
import { Environment, Net, ServiceAuth } from '../net';
import { randomBytes } from 'crypto';
import { Response } from '../../Native';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('chat service api', () => {
  it('converts NetError to native', () => {
    expect(() => Native.TESTING_ChatServiceErrorConvert())
      .throws(LibSignalErrorBase)
      .with.property('code', ErrorCode.IoError);
  });

  it('converts Response object to native', () => {
    const status = 200;
    const headers: ReadonlyArray<[string, string]> = [
      ['user-agent', 'test'],
      ['forwarded', '1.1.1.1'],
    ];
    const expectedWithContent: Response = {
      status: status,
      message: undefined,
      headers: headers,
      body: Buffer.from('content'),
    };
    const expectedWithoutContent: Response = {
      status: status,
      message: undefined,
      headers: headers,
      body: undefined,
    };
    expect(Native.TESTING_ChatServiceResponseConvert(true)).deep.equals(
      expectedWithContent
    );
    expect(Native.TESTING_ChatServiceResponseConvert(false)).deep.equals(
      expectedWithoutContent
    );
  });

  it('converts DebugInfo object to native', () => {
    const expected = {
      connectionReused: true,
      reconnectCount: 2,
      ipType: 1,
    };
    expect(Native.TESTING_ChatServiceDebugInfoConvert()).deep.equals(expected);
  });

  it('constructs request object correctly', () => {
    const verb = 'GET';
    const path = '/test';
    const userAgent = 'test';
    const forwarded = '1.1.1.1';
    const content = Buffer.from('content');
    const headers: Array<[string, string]> = [
      ['user-agent', userAgent],
      ['forwarded', forwarded],
    ];
    const request = Net.buildHttpRequest({
      verb: verb,
      path: path,
      headers: headers,
      body: content,
    });
    expect(Native.TESTING_ChatRequestGetMethod(request)).equals(verb);
    expect(Native.TESTING_ChatRequestGetPath(request)).equals(path);
    expect(Native.TESTING_ChatRequestGetBody(request)).deep.equals(content);
    expect(
      Native.TESTING_ChatRequestGetHeaderValue(request, 'user-agent')
    ).equals(userAgent);
    expect(
      Native.TESTING_ChatRequestGetHeaderValue(request, 'forwarded')
    ).equals(forwarded);
  });
});

describe('cdsi lookup', () => {
  const e164Both = '+18005551011';
  const e164Pni = '+18005551012';

  const aciUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
  const pniUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

  const debugPermitsUsed = 123;

  const aci: string = Aci.fromUuid(aciUuid).getServiceIdString();
  const pni: string = Pni.fromUuid(pniUuid).getServiceIdString();

  describe('response conversion', () => {
    it('converts to native', async () => {
      const expectedEntries = new Map([
        [e164Both, { aci: aci, pni: pni }],
        [e164Pni, { aci: undefined, pni: pni }],
      ]);

      const expected = {
        entries: expectedEntries,
        debugPermitsUsed: debugPermitsUsed,
      };

      const asyncContext = Native.TokioAsyncContext_new();
      const result = await Native.TESTING_CdsiLookupResponseConvert({
        _nativeHandle: asyncContext,
      });
      expect(result).deep.equals(expected);
    });

    it('converts errors to native', () => {
      expect(() => Native.TESTING_CdsiLookupErrorConvert())
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.IoError);
    });
  });
});

describe('SVR3', () => {
  const TIMEOUT = 5000;
  const USERNAME = randomBytes(16).toString('hex');
  const SVR3 = new Net(Environment.Staging).svr3;

  function make_auth(): Readonly<ServiceAuth> {
    const otp = Native.CreateOTPFromBase64(
      USERNAME,
      // Empty string is a valid base64 encoding
      process.env.ENCLAVE_SECRET || ''
    );
    return { username: USERNAME, password: otp };
  }

  describe('Backup', () => {
    // It is OK to reuse the auth in "input validation" tests.
    const AUTH = make_auth();

    it('maxTries must be positive', () => {
      const secret = randomBytes(32);
      return expect(SVR3.backup(secret, 'password', 0, AUTH, TIMEOUT)).to
        .eventually.be.rejected;
    });

    it('Secret must be 32 bytes', () => {
      const secret = randomBytes(42);
      return expect(SVR3.backup(secret, 'password', 1, AUTH, TIMEOUT)).to
        .eventually.be.rejected;
    });
  });

  describe('Restore', () => {
    it('Empty share set', () => {
      const auth = make_auth();
      const shareSet = Buffer.alloc(0);
      return expect(
        SVR3.restore('password', shareSet, auth, TIMEOUT)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    });

    it('Share set bad format', () => {
      const auth = make_auth();
      const shareSet = Buffer.from([42]);
      return expect(
        SVR3.restore('password', shareSet, auth, TIMEOUT)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    });
  });

  // Integration tests require access to the staging environment and make real
  // network calls and as such require the secret (and lacking the secret will
  // not be run).
  describe('Integration tests', function (this: Mocha.Suite) {
    before(() => {
      if (!process.env.ENCLAVE_SECRET) {
        this.ctx.skip();
      }
    });

    it('Backup and restore work in staging', async () => {
      const auth = make_auth();
      const secret = randomBytes(32);
      const shareSet = await SVR3.backup(secret, 'password', 10, auth, TIMEOUT);
      const restoredSecret = await SVR3.restore(
        'password',
        shareSet,
        auth,
        TIMEOUT
      );
      expect(restoredSecret).to.eql(secret);
    }).timeout(10000);

    it('Restore with wrong password', async () => {
      const auth = make_auth();
      const secret = randomBytes(32);
      const shareSet = await SVR3.backup(secret, 'password', 10, auth, TIMEOUT);
      return expect(SVR3.restore('wrong password', shareSet, auth, TIMEOUT))
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.SvrRestoreFailed);
    }).timeout(10000);

    it('Restore with corrupted share set', async () => {
      const auth = make_auth();
      const secret = randomBytes(32);
      const shareSet = await SVR3.backup(secret, 'password', 10, auth, TIMEOUT);
      // The first byte is the serialization format version, changing that
      // _will_ fail (checked in the other test). Changing the actual share set
      // value makes a more interesting test case.
      shareSet[1] ^= 0xff;
      return expect(
        SVR3.restore('password', shareSet, auth, TIMEOUT)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    }).timeout(10000);

    it('Exceed maxTries', async () => {
      const auth = make_auth();
      const secret = randomBytes(32);
      const shareSet = await SVR3.backup(secret, 'password', 1, auth, TIMEOUT);
      await SVR3.restore('password', shareSet, auth, TIMEOUT);
      return expect(SVR3.restore('password', shareSet, auth, TIMEOUT))
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.SvrDataMissing);
    });

    it('Timeout', async () => {
      const auth = make_auth();
      const secret = randomBytes(32);
      const SHORT_TIMEOUT = 100;
      return expect(SVR3.backup(secret, 'password', 10, auth, SHORT_TIMEOUT))
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.IoError);
    });
  });
});
