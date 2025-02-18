const connect = require('connect');
const http = require('http');
const passport = require('passport');

const CertHeaderStrategy = require('../lib');

const PORT = 3443;

// A list of valid user IDs
// test/data contains certs for users bob and ann.
// Ann is in the list, so requests with that key/cert will be authorized.
// Bob is not in the list, so requests will not be authorized.
const users = ['client'];

/**
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

http.createServer(app).listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
