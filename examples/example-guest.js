const http = require('http');
const passport = require('passport');
const express = require('express');

const CertHeaderStrategy = require('../lib');

const users = ['client'];
const PORT = 3443;

function authenticatedOrGuest(req, res, next) {
  return passport.authenticate('cert-header', { session: false }, (err, user) => {
    if (err) return next(err);
    if (user) req.user = user;
    next();
  })(req, res, next);
}

function lookupUser(cn, done) {
  const user = users.indexOf(cn) >= 0 ? { username: cn } : null;
  done(null, user);
}

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
        console.log(`${msg} - ✔️`);
        done(null, user);
      }
    });
  }
}

passport.use(new CertHeaderStrategy({ header: 'client-cert' }, authenticate));
const app = express();
app.use(passport.initialize());

app.get('/', authenticatedOrGuest, (req, res) => {
  let message;
  if (req.user) {
    message = JSON.stringify(req.user);
  } else {
    message = 'Guest!';
  }
  res.end(message);
});

http.createServer(app).listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
