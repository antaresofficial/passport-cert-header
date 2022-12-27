// Module dependencies.
var passport = require('passport-strategy');
var tls = require('tls');
var net = require('net');
var util = require('util');

/**
 * Create a new `Strategy` object.
 *
 * @classdesc This `Strategy` authenticates requests that carry a forwarded client cert
 * in the header of the request.
 * These credentials are typically
 * submitted by the router (i.e. traefik).
 *
 * @public
 * @class
 * @augments base.Strategy
 * @param {Object} [options]
 * @param {string} [options.header='client-cert'] - Header field name where
 *          the client cert is found.
 * @param {boolean} [options.passReqToCallback=false] - When `true`, the
 *          `verify` function receives the request object as the first argument,
 *          in accordance with `{@link Strategy~verifyWithReqFn}`.
 * @param {Strategy~verifyFn|Strategy~verifyWithReqFn} verify - Function which
 *          verifies client cert.
 *
 * @example
 * var CertHeaderStrategy = require('passport-cert-header').Strategy;
 *
 * new CertHeaderStrategy({ header: 'client-cert' }, function({ cert }, cb) {
 *   users.findOne({ username: cert.subject.CN }, function(err, user) {
 *     if (err) { return cb(err); }
 *     if (!user) { return cb(null, false, { message: 'Incorrect CN in cert.' }); }
 *
 *     return cb(null, user);
  *   });
 * });
 *
 * @example <caption>Construct strategy using top-level export.</caption>
 * var LocalStrategy = require('passport-local');
 *
 * new LocalStrategy({ header: 'client-cert' }, function({ cert }, cb) {
 *   // ...
 * });
 */
function Strategy(options, verify) {
  if (!options.header) {
    throw new Error('Cert header strategy requires a header option');
  }

  if (!verify) { throw new TypeError('Cert header authentication strategy requires a verify function'); }

  this.header = String(options.header).toLowerCase();

  passport.Strategy.call(this);

  /** The name of the strategy, which is set to `'cert-header'`.
   *
   * @type {string}
   * @readonly
   */
  this.name = 'cert-header';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by verifying forwarded client cert.
 *
 * This function is protected, and should not be called directly.  Instead,
 * use `passport.authenticate()` middleware and specify the {@link Strategy#name `name`}
 * of this strategy and any options.
 *
 * @protected
 * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
 *          object.
 * @param {Object} [options]
 * @param {string} [options.badRequestMessage='Missing cert'] - Message
 *          to display when a request does not include a client cert.
 *          Used in conjunction with `failureMessage` or `failureFlash` options.
 *
 * @example
 * passport.authenticate('cert-header');
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};

  const foundHeaderValue = req.headers[this.header];

  if (!foundHeaderValue) {
    return this.fail({ message: options.badRequestMessage || 'Missing cert' }, 401);
  }

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

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

  try {
    if (self._passReqToCallback) {
      this._verify(req, { cert }, verified);
    } else {
      this._verify({ cert }, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};

// Export `Strategy`.
module.exports = Strategy;

/**
 * Verifies `cert` and yields authenticated user.
 *
 * This function is called by `{@link Strategy}` to verify a cert,
 * and must invoke `cb` to yield the result.
 *
 * @callback Strategy~verifyFn
 * @param {PeerCertificate} cert - The forwarded client cert received. The Node.js {@link https://nodejs.org/api/tls.html#certificate-object `IncomingMessage`} object
 * @param {function} cb
 * @param {?Error} cb.err - An `Error` if an error occured; otherwise `null`.
 * @param {Object|boolean} cb.user - An `Object` representing the authenticated
 *          user if verification was successful; otherwise `false`.
 * @param {Object} cb.info - Additional application-specific context that will be
 *          passed through for further request processing.
 */

/**
 * Verifies `cert` and yields authenticated user.
 *
 * This function is called by `{@link Strategy}` to verify a username and
 * password when the `passReqToCallback` option is set, and must invoke `cb` to
 * yield the result.
 *
 * @callback Strategy~verifyWithReqFn
 * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
 *          object.
 * @param {PeerCertificate} cert - The forwarded client cert received. The Node.js {@link https://nodejs.org/api/tls.html#certificate-object `IncomingMessage`} object
 * @param {function} cb
 * @param {?Error} cb.err - An `Error` if an error occured; otherwise `null`.
 * @param {Object|boolean} cb.user - An `Object` representing the authenticated
 *          user if verification was successful; otherwise `false`.
 * @param {Object} cb.info - Additional application-specific context that will be
 *          passed through for further request processing.
 */
