import { assert } from 'chai';
import connect from 'connect';
import fs from 'fs';
import http from 'http';
import { afterEach, describe, it } from 'mocha';
import passport from 'passport';
import path from 'path';
import request from 'request';
import CertHeaderStrategy from '../src/index.mjs';
import helpers from './helpers.js';

const HTTP_PORT = 3080;

const pem = fs.readFileSync(path.join(helpers.__dirname, 'data', 'client.crt'), { encoding: 'utf8' });
const encodedPem = helpers.extractBody(pem);

const headerName = 'Client-Cert';

describe('Cert header strategy integration', () => {
  let server;

  function createHttpServer(app, done) {
    server = http.createServer(app).listen(HTTP_PORT, done);
  }

  afterEach((done) => {
    server.close(done);
    server = null;
  });

  describe('handling a request with a valid client cert', () => {
    const validRequestOptions = {
      hostname: 'localhost',
      url: `http://localhost:${HTTP_PORT}`,
      path: '/',
      method: 'GET',
      headers: {
        [headerName]: encodedPem,
      },
    };

    it('passes the certificate to the verify callback', (done) => {
      const app = connect();

      const strategy = new CertHeaderStrategy({ header: headerName }, ({ cert }, d) => {
        assert.strictEqual(
          cert.fingerprint,
          'E1:6E:DD:97:28:A6:DD:48:63:92:F1:C8:98:0A:48:ED:4E:4A:52:82',
        );
        const { subject } = cert;
        d(null, { cn: subject.CN });
      });

      passport.use(strategy);
      app.use(passport.initialize());
      app.use(passport.authenticate('cert-header', { session: false }));

      app.use((req, res) => {
        assert.isTrue(req.isAuthenticated());
        res.end(JSON.stringify(req.user));
      });

      createHttpServer(app, () => {
        request.get(validRequestOptions, (err, res) => {
          assert.equal(res.statusCode, 200);
          assert.deepEqual(res.body, '{"cn":"client"}');
          done();
        });
      });
    });
  });

  describe('handling a request with no client cert', () => {
    const noCertRequestOptions = {
      hostname: 'localhost',
      url: `http://localhost:${HTTP_PORT}`,
      path: '/',
      method: 'GET',
    };

    it('rejects authorization without calling the verify callback', (done) => {
      const app = connect();

      const strategy = new CertHeaderStrategy({ header: headerName }, (() => {
        assert.fail(); // should not be called
      }));

      passport.use(strategy);
      app.use(passport.initialize());
      app.use(passport.authenticate('cert-header', { session: false }));

      app.use(() => {
        assert.fail(); // should not be called
      });

      createHttpServer(app, () => {
        request.get(noCertRequestOptions, (err, res) => {
          assert.equal(res.statusCode, 401);
          done();
        });
      });
    });
  });
});
