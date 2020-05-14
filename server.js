#!/usr/bin/env node

'use strict';

/* ===============
    CONFIGURATION
   =============== */

var CONFIG = {
  'wssHost' : '127.0.0.1',
  'wssPort' : '8080',
  'ecdsaPrivate' : '*** have to generate it for yourself (via ecsda_generate.js) *** and update the puplic key accordingly (in bundle_chat.js) ***',
};

/* =====================
    INITIALIZE PACKAGES
   ===================== */

var UUIDV4 = require('uuid/v4'),
    ELLIPTIC = require('elliptic').ec,
    ECDH = new ELLIPTIC('p521'),
    ED = new ELLIPTIC('ed25519'),
    ECDSA = ED.keyFromPrivate(CONFIG.ecdsaPrivate, 'hex'),
    AES = require('aes-js'),
    WS = require('ws').Server;

/* ======================
    SET GLOBAL VARIABLES
   ====================== */

var CLIENTS = {};
var GROUPS = {};

/* =========================
    CREATE WEBSOCKET SERVER
   ========================= */

var WSS = new WS({
  'host' : CONFIG.wssHost,
  'port' : CONFIG.wssPort,
});

WSS.on('connection', function ( client ) {

  /* =======================
      HANDLE NEW CONNECTION
     ======================= */

  var connectionID = UUIDV4().replace(/\-/gmi, '');

  if (
    typeof(CLIENTS[connectionID]) !== 'object'
  ) {

    CLIENTS[connectionID] = {
      'connection' : client,
      'group' : null,
      'ecdh' : ECDH.genKeyPair(),
      'aes' : {
        'send' : null,
        'receive' : null,
      },
    };

    console.log('Client connected [clients: ' + Object.keys(CLIENTS).length + ', groups: ' + Object.keys(GROUPS).length + ', rss: ' + ( process.memoryUsage().rss / 1024 / 1024 ).toFixed(2) + ']');

    // Send server ecdh public key

    sendMessage(connectionID, {
      'action' : 'ecdhPublicKey',
      'payload' : CLIENTS[connectionID].ecdh.getPublic('hex'),
    });

  } else {
    client.close();
  };

  /* =================
      HANDLE MESSAGES
     ================= */

  client.on('message', function ( data ) {
    if (
      typeof(CLIENTS[connectionID]) === 'object' &&
      typeof(data) === 'string'
    ) {

      // Handle ping requests

      if (
        data === '*PING*'
      ) {

        try {
          CLIENTS[connectionID].connection.send('*PONG*', {
            'binary' : false,
            'mask' : false,
          });
        } catch ( error ) {
          console.log(error);
        };

        return;

      };

      // Decrypt raw data if necessary then parse message object

      var message = {};

      try {
        if (
          CLIENTS[connectionID].aes.send !== null &&
          CLIENTS[connectionID].aes.receive !== null
        ) {
          message = JSON.parse(convertBytesToString(CLIENTS[connectionID].aes.receive.decrypt(convertBase64ToBytes(data))));
        } else {
          message = JSON.parse(convertBytesToString(convertBase64ToBytes(data)));
        };
      } catch ( error ) {
        console.log(error);
        return;
      };

      // Handle message object action

      if (
        typeof(message.action) === 'string'
      ) {
        switch (
          message.action
        ) {

          /* ---------------
             Ecdh public key
             --------------- */

          case 'ecdhPublicKey':

            // message.payload - string - contains the client ecdh public key

            if (
              typeof(message.payload) !== 'string'
            ) {
              break;
            };

            // Calculate the ecdh shared key from the client ecdh public key then set aes resources

            try {

              var sharedKey = CLIENTS[connectionID].ecdh.derive(ECDH.keyFromPublic(message.payload, 'hex').getPublic()).toString(16);
              sharedKey = ( sharedKey.substr(0, 32) + sharedKey.substr(-32, 32) );

              CLIENTS[connectionID].aes.send = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter(1));
              CLIENTS[connectionID].aes.receive = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter(2147483648));

            } catch ( error ) {
              console.log(error);
              break;
            };

            // Send connection id

            sendMessage(connectionID, {
              'action' : 'connectionID',
              'payload' : connectionID,
            });

            break;

          /* -----------------
             Participate group
             ----------------- */

          case 'participateGroup':

            // message.payload - string - contains the group name

            if (
              CLIENTS[connectionID].aes.send === null ||
              CLIENTS[connectionID].aes.receive === null ||
              typeof(message.payload) !== 'string' ||
              message.payload.length < 1
            ) {
              break;
            };

            // Set group

            CLIENTS[connectionID].group = message.payload;

            // Add connection id to the group

            var clientGroup = CLIENTS[connectionID].group;

            if (
              typeof(GROUPS[clientGroup]) !== 'object'
            ) {
              GROUPS[clientGroup] = [ connectionID ];
            } else {
              GROUPS[clientGroup].push(connectionID);
            }

            // Send list group to all members

            GROUPS[clientGroup].map(function ( member, index ) {
              sendMessage(member, {
                'action' : 'listGroup',
                'payload' : GROUPS[clientGroup].filter(function ( value ) {
                  return(
                    value !== member
                    ? true
                    : false
                  );
                }),
              });
            });

            break;

          /* -------------
             Message group
             ------------- */

          case 'messageGroup':

            // message.payload - object - keys contains the connection id of the group member and values contains their messages

            if (
              CLIENTS[connectionID].aes.send === null ||
              CLIENTS[connectionID].aes.receive === null ||
              CLIENTS[connectionID].group === null ||
              typeof(message.payload) !== 'object'
            ) {
              break;
            };

            Object.keys(message.payload).map(function ( member, index ) {
              if (
                typeof(message.payload[member]) === 'string' &&
                typeof(CLIENTS[member]) === 'object' &&
                CLIENTS[member].aes.send !== null &&
                CLIENTS[member].aes.receive !== null &&
                CLIENTS[member].group !== null &&
                CLIENTS[connectionID].group === CLIENTS[member].group
              ) {

                // Send the message to the group member

                sendMessage(member, {
                  'action' : 'messageGroupMember',
                  'payload' : {
                    'member' : connectionID,
                    'message' : message.payload[member],
                  },
                });

              };
            });

            break;

          /* --------------------
             Message group member
             -------------------- */

          case 'messageGroupMember':

            // message.payload.member - string - contains the connection id of the group member
            // message.payload.message - anything - contains the message to the group member

            if (
              CLIENTS[connectionID].aes.send === null ||
              CLIENTS[connectionID].aes.receive === null ||
              CLIENTS[connectionID].group === null ||
              typeof(message.payload) !== 'object' ||
              typeof(message.payload.member) !== 'string' ||
              typeof(message.payload.message) === 'undefined' ||
              typeof(CLIENTS[message.payload.member]) !== 'object' ||
              CLIENTS[message.payload.member].aes.send === null ||
              CLIENTS[message.payload.member].aes.receive === null ||
              CLIENTS[message.payload.member].group === null ||
              CLIENTS[connectionID].group !== CLIENTS[message.payload.member].group
            ) {
              break;
            };

            // Send the message to the group member

            sendMessage(message.payload.member, {
              'action' : 'messageGroupMember',
              'payload' : {
                'member' : connectionID,
                'message' : message.payload.message,
              },
            });

            break;

        };
      };

    };
  });

  /* ======================
      HANDLE DISCONNECTION
     ====================== */

  client.on('close', function () {

    // Sanitize clients and groups

    if (
      typeof(CLIENTS[connectionID]) === 'object'
    ) {

      var clientGroup = CLIENTS[connectionID].group;

      if (
        clientGroup !== null &&
        typeof(GROUPS[clientGroup]) === 'object' &&
        GROUPS[clientGroup].indexOf(connectionID) > -1
      ) {

        GROUPS[clientGroup].splice(GROUPS[clientGroup].indexOf(connectionID), 1);

        if (
          GROUPS[clientGroup].length === 0
        ) {
          delete(GROUPS[clientGroup]);
        } else {

          // Send list group to all members

          GROUPS[clientGroup].map(function ( member, index ) {
            sendMessage(member, {
              'action' : 'listGroup',
              'payload' : GROUPS[clientGroup].filter(function ( value ) {
                return(
                  value !== member
                  ? true
                  : false
                );
              }),
            });
          });

        };

      };

      delete(CLIENTS[connectionID]);

    };

    client = null;

    console.log('Client disconnected [clients: ' + Object.keys(CLIENTS).length + ', groups: ' + Object.keys(GROUPS).length + ', rss: ' + ( process.memoryUsage().rss / 1024 / 1024 ).toFixed(2) + ']');

  });

});

/* =====================
    MESSAGING FUNCTIONS
   ===================== */

// Send message

function sendMessage ( connectionID, message ) {
  if (
    typeof(CLIENTS[connectionID]) === 'object'
  ) {

    var data = {
      'message' : message,
      'signature' : signMessage(message),
    };

    // Encrypt message if necessary then send message object

    try {
      if (
        CLIENTS[connectionID].aes.send !== null &&
        CLIENTS[connectionID].aes.receive !== null
      ) {
        CLIENTS[connectionID].connection.send(convertBytesToBase64(CLIENTS[connectionID].aes.send.encrypt(convertStringToBytes(JSON.stringify(data)))), {
          'binary' : false,
          'mask' : false,
        });
      } else {
        CLIENTS[connectionID].connection.send(convertBytesToBase64(convertStringToBytes(JSON.stringify(data))), {
          'binary' : false,
          'mask' : false,
        });
      };
    } catch ( error ) {
      console.log(error);
    };

  };
};

// Sign message

function signMessage ( message ) {

  var signature = '';

  try {
    signature = ECDSA.sign(JSON.stringify(message)).toDER('hex');
  } catch ( error ) {
    console.log(error);
  };

  return(signature);

};

/* =========================
    MISCELLANEOUS FUNCTIONS
   ========================= */

// Convert hex to bytes

function convertHexToBytes ( hex ) {

  var bytes = [];

  for (
    var i = 0,
        j = hex.length;
    i < j;
    i += 2
  ) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  };

  return(bytes);

};

// Convert string to bytes

function convertStringToBytes ( string ) {

  var bytes = [],
      p = 0;

  for (
    var i = 0;
    i < string.length;
    i++
  ) {

    var c = string.charCodeAt(i);

    if (
      c < 128
    ) {
      bytes[p++] = c;
    } else if (
      c < 2048
    ) {
      bytes[p++] = ( c >> 6 ) | 192;
      bytes[p++] = ( c & 63 ) | 128;
    } else if (
      ( ( c & 0xFC00 ) == 0xD800 ) &&
      ( i + 1 ) < string.length &&
      ( ( string.charCodeAt(i + 1) & 0xFC00 ) == 0xDC00 )
    ) {

      c = 0x10000 + ( ( c & 0x03FF ) << 10 ) + ( string.charCodeAt(++i) & 0x03FF );

      bytes[p++] = ( c >> 18 ) | 240;
      bytes[p++] = ( ( c >> 12 ) & 63 ) | 128;
      bytes[p++] = ( ( c >> 6 ) & 63 ) | 128;
      bytes[p++] = ( c & 63 ) | 128;

    } else {
      bytes[p++] = ( c >> 12 ) | 224;
      bytes[p++] = ( ( c >> 6 ) & 63 ) | 128;
      bytes[p++] = ( c & 63 ) | 128;
    };

  };

  return(bytes);

};

// Convert bytes to string

function convertBytesToString ( bytes ) {

  var string = [],
      pos = 0,
      c = 0;

  while (
    pos < bytes.length
  ) {

    var c1 = bytes[pos++];

    if (
      c1 < 128
    ) {
      string[c++] = String.fromCharCode(c1);
    } else if (
      c1 > 191 &&
      c1 < 224
    ) {

      var c2 = bytes[pos++];

      string[c++] = String.fromCharCode(( c1 & 31 ) << 6 | c2 & 63);

    } else if (
      c1 > 239 &&
      c1 < 365
    ) {

      var c2 = bytes[pos++];
      var c3 = bytes[pos++];
      var c4 = bytes[pos++];
      var u = ( ( c1 & 7 ) << 18 | ( c2 & 63 ) << 12 | ( c3 & 63 ) << 6 | c4 & 63 ) - 0x10000;

      string[c++] = String.fromCharCode(0xD800 + ( u >> 10 ));
      string[c++] = String.fromCharCode(0xDC00 + ( u & 1023 ));

    } else {

      var c2 = bytes[pos++];
      var c3 = bytes[pos++];

      string[c++] = String.fromCharCode(( c1 & 15 ) << 12 | ( c2 & 63 ) << 6 | c3 & 63);

    };

  };

  return(string.join(''));

};

// Base64 encodings and lookup

var Base64Encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='.split('');
var base64Lookup = [];

for (
  var i = 0;
  i < Base64Encodings.length;
  ++i
) {
  base64Lookup[Base64Encodings[i].charCodeAt(0)] = i;
};

// Convert base64 to bytes

function convertBase64ToBytes ( base64 ) {

  base64 = base64.replace(/[^A-Za-z0-9\+\/\=]+/g, '');

  var bytes = [],
      base64Length = base64.length,
      a, b, c, d;

  if (
    ( base64Length % 4 ) != 0
  ) {
    return(bytes);
  };

  for (
    var i = 0;
    i < base64Length;
    i += 4
  ) {

    a = base64Lookup[base64.charCodeAt(i)];
    b = base64Lookup[base64.charCodeAt(( i + 1 ))];
    c = base64Lookup[base64.charCodeAt(( i + 2 ))];
    d = base64Lookup[base64.charCodeAt(( i + 3 ))];

    bytes.push(( ( a << 2 ) | ( b >> 4 ) ));

    if (
      c != 64
    ) {
      bytes.push(( ( ( b & 15 ) << 4 ) | ( c >> 2 ) ));
    };

    if (
      d != 64
    ) {
      bytes.push(( ( ( c & 3 ) << 6 ) | ( d & 63 ) ));
    };

  };

  return(bytes);

};

// Convert bytes to base64

function convertBytesToBase64 ( bytes ) {

  var base64 = '',
      bytesLength = bytes.length,
      bytesRemainder = ( bytesLength % 3 );

  for (
    var i = 0;
    i < bytesLength;
    i += 3
  ) {
    base64 += Base64Encodings[( bytes[i] >> 2 )];
    base64 += Base64Encodings[( ( ( bytes[i] & 3 ) << 4 ) | ( bytes[( i + 1 )] >> 4 ) )];
    base64 += Base64Encodings[( ( ( bytes[( i + 1 )] & 15 ) << 2 ) | ( bytes[( i + 2 )] >> 6 ) )];
    base64 += Base64Encodings[( bytes[( i + 2 )] & 63 )];
  };

  if (
    bytesRemainder == 2
  ) {
    base64 = base64.substring(0, ( base64.length - 1 )) + '=';
  } else if (
    bytesRemainder == 1
  ) {
    base64 = base64.substring(0, ( base64.length - 2 )) + '==';
  };

  return(base64);

};
