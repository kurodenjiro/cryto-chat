#!/usr/bin/env node

'use strict';

var ELLIPTIC = require('elliptic').ec,
    ECDSA = new ELLIPTIC('ed25519');

var key = ECDSA.genKeyPair();

console.log(key.getPrivate('hex'));
console.log(key.getPublic('hex'));
