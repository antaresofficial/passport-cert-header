import connect from 'connect';
import http from 'http';
import passport from 'passport';

import CertHeaderStrategy from '../src/index.mjs';

const PORT = 3443;

// A list of valid user IDs
// test/data contains certs for users bob and ann.
// Ann is in the list, so requests with that key/cert will be authorized.
// Bob is not in the list, so requests will not be authorized.
const users = ['client'];

/*
 * Dummy user lookup method - simulates database lookup
 */
function lookupUser(cn, done) {
  const user = users.indexOf(cn) >= 0 ? { username: cn } : null;
  done(null, user);
}

/**
 * Authentication callback for authentication
 *  - Look up a user by ID (which, in this simple case, is identical
 *    to the certificate's Common Name attribute).
 */
function authenticate(payload, done) {
  const { cert } = payload;
  const { subject } = cert;
  let msg = 'Attempting PKI authentication';

  if (!subject) {
    console.log(`${msg} ✘ - no subject`);
    done(null, false);
  } else if (!subject.CN) {
    console.log(`${msg} ✘ - no client CN`);
    done(null, false);
  } else {
    const cn = subject.CN;

    lookupUser(cn, (err, user) => {
      msg = `Authenticating ${cn} with certificate`;

      if (!user) {
        console.log(`${msg} ✘ - no such user`);
        done(null, false);
      } else {
        console.log(`${msg} - ✔`);
        done(null, user);
      }
    });
  }
}

passport.use(new CertHeaderStrategy({ header: 'client-cert' }, authenticate));

const app = connect();
app.use(passport.initialize());
app.use(passport.authenticate('cert-header', { session: false }));
app.use((req, res) => {
  res.end(JSON.stringify(req.user));
});

// Test curl command:
// $ curl -k -H "client-cert: MIIDLTCCAhUCFHYMf3ef92Crz5uqxBeOWh%2B3yDqOMA0GCSqGSIb3DQEBCwUAMIGP%0D%0AMQswCQYDVQQGEwJVSzEYMBYGA1UECAwPR2xvdWNlc3RlcnNoaXJlMRMwEQYDVQQH%0D%0ADApDaGVsdGVuaGFtMQ8wDQYDVQQKDAZSaXBqYXIxFDASBgNVBAsMC0VuZ2luZWVy%0D%0AaW5nMQswCQYDVQQDDAJjYTEdMBsGCSqGSIb3DQEJARYOY2FAZXhhbXBsZS5jb20w%0D%0AIBcNMjIxMjE0MTYzODM0WhgPMjA1MDA0MzAxNjM4MzRaMIGXMQswCQYDVQQGEwJV%0D%0ASzEYMBYGA1UECAwPR2xvdWNlc3RlcnNoaXJlMRMwEQYDVQQHDApDaGVsdGVuaGFt%0D%0AMQ8wDQYDVQQKDAZSaXBqYXIxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ8wDQYDVQQD%0D%0ADAZjbGllbnQxITAfBgkqhkiG9w0BCQEWEmNsaWVudEBleGFtcGxlLmNvbTCBnzAN%0D%0ABgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAnVUT%2BTQGO86Lkmh3fYtjd0ItHyIXvjDT%0D%0A%2BPSahcg6XAfIQ6%2Fr9%2FA8NqJAIV9RWs705cgF3%2B3Yrmb6Db34oAXk5hb2%2BGUi2NGD%0D%0AFg2Bf%2BKVUwVPhfgOepTFJZ9UaMzp6j8hEs%2FYM4sQZ6U2pC0GXaG3bwat%2FH6mCYhU%0D%0AgdxXnApavLECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcTsKdls1VHMDYW3Vz98C%0D%0AhxFru2w%2BLECuwn9LUJxvbix%2FDYcFBb8vrEd5OR%2BPpy%2FHKv70ocCW9PbE79UzmJC1%0D%0A5daPpRWnb9H7maIQrrqKmk4Hg5KuQ4l74G1gHbnZgrBDE4XYewCjdRl3V8wQM7An%0D%0A%2BMPCuhmE%2F4p3dP4mbaxcWQtJs2R9ZN47LB6zxkz1ivahlGLIV6dH5txEpD7Up4cr%0D%0ABY0OIyDsMDiSnmtebSGKPGuYox5S%2BDBiFZkG6vwv%2FdSKYNhPeCQhCoQTA9DF2%2B4Q%0D%0AHl1dE24sbMgcPPnz2SE%2F2CK5Pix9fdn1HJv6QYaZsooe%2BcrC9ITDX76yi8ZxAXn2%0D%0Ayg%3D%3D" http://localhost:3443

http.createServer(app).listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
