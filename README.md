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

## Test

    npm install
    npm test

## Licence

[The MIT Licence](http://opensource.org/licenses/MIT)
