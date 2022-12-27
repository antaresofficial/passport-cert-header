const chai = require('chai');
const fs = require('fs');
const { beforeEach, describe, it } = require('mocha');
const path = require('path');

const Strategy = require('../lib');
const helpers = require('./helpers');

const pem = fs.readFileSync(path.join(__dirname, 'data', 'client.crt'), { encoding: 'utf8' });
const body = helpers.extractBody(pem);

// eslint-disable-next-line no-unused-vars
const should = chai.should();

describe('Cert header strategy', () => {
  let strategy = new Strategy({ header: 'something' }, (() => { }));

  it('should be named cert-header', () => {
    strategy.name.should.equal('cert-header');
  });

  it('should require a verify function and a header option', () => {
    (function () {
      new Strategy();
    }).should.throw(Error);

    (function () {
      new Strategy({});
    }).should.throw(Error);

    const f = function () { };

    (function () {
      new Strategy({}, f);
    }).should.throw(Error);

    // should not throw an error
    new Strategy({ header: 'something' }, f);
  });

  describe('strategy authenticating a request', () => {
    let req;
    const headers = { h1: body, h2: 'header two', h3: 'header three' };
    const options = { header: 'h1' };
    const origCert = helpers.getCert(pem);
    let failed;
    let succeeded;
    let passedToVerify;

    const fail = () => { failed = true; };
    const success = () => { succeeded = true; };
    const err = () => { throw new Error('should not be called'); };

    beforeEach(() => {
      strategy = new Strategy(options, (cert) => {
        passedToVerify = cert;
      });

      failed = false;
      succeeded = false;
      passedToVerify = null;

      strategy.fail = fail;
      strategy.success = success;
      strategy.error = err;
    });

    it('should fail if no headers are provided', () => {
      req = helpers.dummyReq(null, null, {});

      strategy.authenticate(req);
      failed.should.eq(true);
    });

    it('should fail if the cert is empty', () => {
      req = helpers.dummyReq(null, null, { headers: { h3: '' } });

      strategy.authenticate(req);
      failed.should.eq(true);
    });

    it('should pass extracted cert to the verify callback', () => {
      req = helpers.dummyReq(null, null, headers);
      strategy.authenticate(req);
      passedToVerify.should.eql({ cert: origCert });
    });

    it('should succeed if the verify callback provided a user', () => {
      strategy = new Strategy(options, ((_cert, done) => {
        done(null, {});
      }));

      strategy.fail = strategy.error = err;
      strategy.success = success;
      req = helpers.dummyReq(null, null, headers);

      strategy.authenticate(req);
      succeeded.should.eq(true);
    });

    it('should fail if the verify callback provided -false- instead of a user', () => {
      strategy = new Strategy(options, ((_cert, done) => {
        done(null, false);
      }));

      strategy.fail = fail;
      strategy.success = strategy.error = err;

      req = helpers.dummyReq(null, null, headers);
      strategy.authenticate(req);

      failed.should.eq(true);
    });

    it('should error if the verify callback provided an error', () => {
      strategy = new Strategy(options, ((_cert, done) => {
        done(new Error('error from verify'));
      }));

      let ok = false;
      strategy.error = () => { ok = true; };
      strategy.success = strategy.fail = err;

      req = helpers.dummyReq(null, null, headers);
      strategy.authenticate(req);

      ok.should.eq(true);
    });

    it('should pass the request object to the verify callback when directed', () => {
      let passedReq;

      strategy = new Strategy({
        passReqToCallback: true,
        header: options.header,
      }, ((request, _cert, done) => {
        passedReq = request;
        done(null, {});
      }));

      strategy.fail = fail;
      strategy.success = success;
      req = helpers.dummyReq(null, null, headers);

      strategy.authenticate(req);

      failed.should.eq(false);
      succeeded.should.eq(true);
      passedReq.should.eq(req);
    });
  });
});
