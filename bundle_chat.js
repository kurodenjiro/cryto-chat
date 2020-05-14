
/* =====================
    INITIALIZE PACKAGES
   ===================== */

ELLIPTIC = require('elliptic').ec;
ECDHP521 = new ELLIPTIC('p521');
ECDHC25519 = new ELLIPTIC('curve25519');
ED = new ELLIPTIC('ed25519');
ECDSA = ED.keyFromPublic('*** public key goes here ***', 'hex');
AES = require('aes-js');
SHA256 = require('js-sha256').sha256;
