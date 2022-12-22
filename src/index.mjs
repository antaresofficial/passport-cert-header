import net from 'net';
import { Strategy } from 'passport-strategy';
import tls from 'tls';

/*
 * passport.js forwarder client certificate strategy
 */
export default class CertHeaderStrategy extends Strategy {
  constructor(options, verify) {
    super();

    this.name = 'cert-header';

    if (!verify) {
      throw new Error('Cert header authentication strategy requires a verify function');
    }

    if (!options.header) {
      throw new Error('Cert header strategy requires a header option');
    }

    Strategy.call(this);
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
    this.header = String(options.header).toLowerCase();
  }

  authenticate(req) {
    const that = this;

    const foundHeaderValue = req.headers[this.header];

    const verified = function verifed(err, user) {
      if (err) {
        return that.error(err);
      }

      if (!user) {
        return that.fail();
      }

      return that.success(user);
    };

    if (foundHeaderValue) {
      const decodedPem = decodeURIComponent(foundHeaderValue);

      const secureContext = tls.createSecureContext({
        cert: [
          '-----BEGIN CERTIFICATE-----',
          decodedPem,
          '-----END CERTIFICATE-----',
        ].join('\n'),
      });

      const secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
      const cert = secureSocket.getCertificate();
      secureSocket.destroy();

      if (this._passReqToCallback) {
        this._verify(req, { cert }, verified);
      } else {
        this._verify({ cert }, verified);
      }
    } else {
      this.fail();
    }
  }
}
