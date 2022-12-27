const net = require('net');
const tls = require('tls');

/*
 * Stub the relevent parts of the request API
 */
const dummyReq = (authorized, cert, headers) => ({
  client: {
    authorized,
  },
  connection: {
    getPeerCertificate() {
      return cert;
    },
  },
  headers,
});

const extractBody = (pem) => {
  const regexp = /(-+BEGIN\s+.*CERTIFICATE[^-]*-+(?:\s|\r|\n)+)([A-Za-z0-9+/\r\n]+={0,2})/g;
  /* extracted body from PEM */
  const encodedPem = encodeURIComponent(regexp.exec(pem)[2]);

  return encodedPem;
};

const getCert = (pem) => {
  const secureContext = tls.createSecureContext({ cert: pem });
  const secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
  const cert = secureSocket.getCertificate();
  secureSocket.destroy();
  return cert;
};

module.exports = {
  dummyReq,
  extractBody,
  getCert,
};
