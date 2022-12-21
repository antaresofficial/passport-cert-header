import path from 'path';
import { fileURLToPath } from 'url';

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

/*
 * __dirname and __filename is not defined in ES module scope
 */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const getEncodedPem = (pem) => {
  const regexp = /(-+BEGIN\s+.*CERTIFICATE[^-]*-+(?:\s|\r|\n)+)([A-Za-z0-9+/\r\n]+={0,2})/g;
  /* extracted body from PEM */
  const encodedPem = encodeURIComponent(regexp.exec(pem)[2]);
  return encodedPem;
};

export default {
  dummyReq,
  getEncodedPem,
  __dirname,
  __filename,
};
