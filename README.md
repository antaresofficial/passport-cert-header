# passport-cert-header

[passport.js]() authentication and authorisation strategy for client certificate received by forwarded header.

passport-cert-header is for process forwarded cert from router to a Node.js application.

## Usage

The strategy constructor requires a verify callback, which will be executed on each authenticated request. It is responsible for checking the validity of the certificate and user authorisation.

### Options

* `passReqToCallback` - optional. Causes the request object to be supplied to the verify callback as the first parameter.

The verify callback is passed with the [client certificate object](https://nodejs.org/api/tls.html#certificate-object) and a `done` callback. The `done` callback must be called as per the [passport.js documentation](http://passportjs.org/guide/configure/).

````javascript
var passport = require('passport');
var CertHeaderStrategy = require('passport-cert-header').Strategy;

passport.use(new CertHeaderStrategy({header: 'client-cert'}, function({ cert: clientCert }, done) {
  var { cn } = clientCert.subject,
      user = null;

  // The CN will typically be checked against a database
  if(cn === 'test-cn') {
    user = { name: 'Test User' }
  }
  
  done(null, user);
}));
````

The verify callback can be supplied with the `request` object by setting the `passReqToCallback` option to `true`, and changing callback arguments accordingly.

````javascript
passport.use(new ClientCertHeaderStrategy({ passReqToCallback: true }, function(req, { cert: clientCert }, done) {
  var { cn } = clientCert.subject,
      user = null;
      
  // The CN will typically be checked against a database
  if(cn === 'test-cn') {
    user = { name: 'Test User' }
  }
  
  done(null, user);
}));
````

## Examples


````sh 
curl -k -H "client-cert: MIIDLTCCAhUCFHYMf3ef92Crz5uqxBeOWh%2B3yDqOMA0GCSqGSIb3DQEBCwUAMIGP%0D%0AMQswCQYDVQQGEwJVSzEYMBYGA1UECAwPR2xvdWNlc3RlcnNoaXJlMRMwEQYDVQQH%0D%0ADApDaGVsdGVuaGFtMQ8wDQYDVQQKDAZSaXBqYXIxFDASBgNVBAsMC0VuZ2luZWVy%0D%0AaW5nMQswCQYDVQQDDAJjYTEdMBsGCSqGSIb3DQEJARYOY2FAZXhhbXBsZS5jb20w%0D%0AIBcNMjIxMjE0MTYzODM0WhgPMjA1MDA0MzAxNjM4MzRaMIGXMQswCQYDVQQGEwJV%0D%0ASzEYMBYGA1UECAwPR2xvdWNlc3RlcnNoaXJlMRMwEQYDVQQHDApDaGVsdGVuaGFt%0D%0AMQ8wDQYDVQQKDAZSaXBqYXIxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ8wDQYDVQQD%0D%0ADAZjbGllbnQxITAfBgkqhkiG9w0BCQEWEmNsaWVudEBleGFtcGxlLmNvbTCBnzAN%0D%0ABgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAnVUT%2BTQGO86Lkmh3fYtjd0ItHyIXvjDT%0D%0A%2BPSahcg6XAfIQ6%2Fr9%2FA8NqJAIV9RWs705cgF3%2B3Yrmb6Db34oAXk5hb2%2BGUi2NGD%0D%0AFg2Bf%2BKVUwVPhfgOepTFJZ9UaMzp6j8hEs%2FYM4sQZ6U2pC0GXaG3bwat%2FH6mCYhU%0D%0AgdxXnApavLECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcTsKdls1VHMDYW3Vz98C%0D%0AhxFru2w%2BLECuwn9LUJxvbix%2FDYcFBb8vrEd5OR%2BPpy%2FHKv70ocCW9PbE79UzmJC1%0D%0A5daPpRWnb9H7maIQrrqKmk4Hg5KuQ4l74G1gHbnZgrBDE4XYewCjdRl3V8wQM7An%0D%0A%2BMPCuhmE%2F4p3dP4mbaxcWQtJs2R9ZN47LB6zxkz1ivahlGLIV6dH5txEpD7Up4cr%0D%0ABY0OIyDsMDiSnmtebSGKPGuYox5S%2BDBiFZkG6vwv%2FdSKYNhPeCQhCoQTA9DF2%2B4Q%0D%0AHl1dE24sbMgcPPnz2SE%2F2CK5Pix9fdn1HJv6QYaZsooe%2BcrC9ITDX76yi8ZxAXn2%0D%0Ayg%3D%3D" http://localhost:3443
````

## Test

    npm install
    npm test

## Licence

[The MIT Licence](http://opensource.org/licenses/MIT)