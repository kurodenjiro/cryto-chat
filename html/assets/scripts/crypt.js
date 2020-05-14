
/* ===================
    CHATCRYPT FACTORY
   =================== */

var ChatCrypt = new function () {

  var self = this;

  /* ===========
      VARIABLES
     =========== */

  var credentials = {
    'userName' : '',
    'groupName' : '',
    'groupPassword' : '',
  };

  var crypt = {
    'ecdh' : null,
    'aes' : {
      'send' : null,
      'receive' : null,
    },
  };

  var connectionID = null;

  var GROUP = {};

  this.connection = null;

  this.status = {
    'connected' : false,
  };

  this.sendPingRequests = null;

  /* =================
      SET CREDENTIALS
     ================= */

  this.setCredentials = function ( userName, groupName, groupPassword ) {
    credentials = {
      'userName' : userName,
      'groupName' : groupName,
      'groupPassword' : groupPassword,
    };
  };

  /* =============
      WSS CONNECT
     ============= */

  this.wssConnect = function () {

    // Show connecting overlay

    showConnecting();

    // Generate ecdh keypair

    crypt.ecdh = ECDHP521.genKeyPair();

    // Create new websocket connection

    try {
      self.connection = new WebSocket(CONFIG.wssURL);
    } catch ( error ) {
      if (
        CONFIG.debug === true
      ) {
        console.log(error);
      };
    };

    /* -------------
       HANDLE ONOPEN
       ------------- */

    self.connection.onopen = function () {

      // Update connected status

      self.status.connected = true;

      // Start sending ping requests

      self.sendPingRequests = setInterval(function () {
        if (
          self.status.connected === true
        ) {
          try {

            self.connection.send('*PING*');

            if (
              CONFIG.debug === true
            ) {
              console.log('SENT PING REQUEST TO SERVER');
            };

          } catch ( error ) {
            if (
              CONFIG.debug === true
            ) {
              console.log(error);
            };
          };
        };
      }, CONFIG.wssPingInterval);

    };

    /* ----------------
       HANDLE ONMESSAGE
       ---------------- */

    self.connection.onmessage = function ( event ) {
      if (
        typeof(event.data) === 'string'
      ) {

        // Ignore pong responses

        if (
          event.data === '*PONG*'
        ) {

          if (
            CONFIG.debug === true
          ) {
            console.log('RECEIVED PONG RESPONSE FROM SERVER');
          };

          return;

        };

        if (
          CONFIG.debug === true
        ) {
          console.log('RECEIVED RAW DATA FROM SERVER:');
          console.log(event.data);
        };

        // Decrypt raw data if necessary then parse message object

        var message = {};

        try {
          if (
            crypt.aes.send !== null &&
            crypt.aes.receive !== null
          ) {
            message = JSON.parse(convertBytesToString(crypt.aes.receive.decrypt(convertBase64ToBytes(event.data))));
          } else {
            message = JSON.parse(convertBytesToString(convertBase64ToBytes(event.data)));
          };
        } catch ( error ) {
          if (
            CONFIG.debug === true
          ) {
            console.log(error);
          };
        };

        // Validate message object

        if (
          typeof(message.message) !== 'object' ||
          typeof(message.message.action) !== 'string' ||
          typeof(message.message.payload) === 'undefined'
        ) {
          return;
        };

        // Validate message signature

        try {
          if (
            typeof(message.signature) !== 'string' ||
            ! ECDSA.verify(JSON.stringify(message.message), message.signature)
          ) {
            return;
          };
        } catch ( error ) {

          if (
            CONFIG.debug === true
          ) {
            console.log(error);
          };

          return;

        };

        // Trim message object

        message = message.message;

        if (
          CONFIG.debug === true
        ) {
          console.log('RECEIVED MESSAGE OBJECT FROM SERVER:');
          console.log(message);
        };

        // Handle message object action

        switch (
          message.action
        ) {

          /* ---------------
             Ecdh public key
             --------------- */

          case 'ecdhPublicKey':

            // message.payload - string - contains the server ecdh public key

            if (
              typeof(message.payload) !== 'string'
            ) {
              break;
            };

            // Send client ecdh public key

            self.sendMessage({
              'action' : 'ecdhPublicKey',
              'payload' : crypt.ecdh.getPublic('hex'),
            });

            // Calculate the ecdh shared key from the server ecdh public key then set aes resources

            try {

              var sharedKey = crypt.ecdh.derive(ECDHP521.keyFromPublic(message.payload, 'hex').getPublic()).toString(16);
              sharedKey = ( sharedKey.substr(0, 32) + sharedKey.substr(-32, 32) );

              crypt.aes.send = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter(2147483648));
              crypt.aes.receive = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter(1));

            } catch ( error ) {
              if (
                CONFIG.debug === true
              ) {
                console.log(error);
              };
            };

            break;

          /* -------------
             Connection id
             ------------- */

          case 'connectionID':

            // message.payload - string - contains connection id

            if (
              crypt.aes.send === null ||
              crypt.aes.receive === null ||
              typeof(message.payload) !== 'string'
            ) {
              break;
            };

            // Set connection id

            connectionID = message.payload;

            // Send participate group

            self.sendMessage({
              'action' : 'participateGroup',
              'payload' : credentials.groupName,
            });

            // Hide connecting overlay

            hideConnecting();

            break;

          /* ----------
             List group
             ---------- */

          case 'listGroup':

            // message.payload - object (array) - contains group members

            if (
              crypt.aes.send === null ||
              crypt.aes.receive === null ||
              typeof(message.payload) !== 'object'
            ) {
              break;
            };

            // Update group members

            Object.keys(GROUP).map(function ( member, index ) {
              if (
                message.payload.indexOf(member) < 0
              ) {
                delete(GROUP[member]);
              };
            });

            var groupMembers = {};

            message.payload.map(function ( member, index ) {
              if (
                typeof(GROUP[member]) !== 'object'
              ) {

                GROUP[member] = {
                  'userName' : null,
                  'crypt' : {
                    'ecdh' : ECDHC25519.genKeyPair(),
                    'aes' : {
                      'send' : null,
                      'receive' : null,
                    },
                  },
                };

                // Send ecdh public key to group member

                self.sendMessageGroupMember(member, {
                  'action' : 'ecdhPublicKey',
                  'payload' : GROUP[member].crypt.ecdh.getPublic('hex'),
                });

              } else if (
                GROUP[member].userName !== null &&
                GROUP[member].crypt.aes.send !== null &&
                GROUP[member].crypt.aes.receive !== null
              ) {
                groupMembers[member] = GROUP[member].userName;
              };
            });

            updateGroupMembers(groupMembers);

            break;

          /* --------------------
             Message group member
             -------------------- */

          case 'messageGroupMember':

            // message.payload.member - string - contains the connection id of the group member
            // message.payload.message - string - contains the message from the group member

            if (
              connectionID === null ||
              crypt.aes.send === null ||
              crypt.aes.receive === null ||
              typeof(message.payload) !== 'object' ||
              typeof(message.payload.member) !== 'string' ||
              typeof(message.payload.message) !== 'string' ||
              typeof(GROUP[message.payload.member]) !== 'object'
            ) {
              break;
            };

            // Decrypt raw message if necessary then parse message group member object

            var messageGroupMember = {};

            try {
              if (
                GROUP[message.payload.member].crypt.aes.send !== null &&
                GROUP[message.payload.member].crypt.aes.receive !== null
              ) {
                messageGroupMember = JSON.parse(convertBytesToString(GROUP[message.payload.member].crypt.aes.receive.decrypt(convertBase64ToBytes(message.payload.message))));
              } else {
                messageGroupMember = JSON.parse(convertBytesToString(convertBase64ToBytes(message.payload.message)));
              };
            } catch ( error ) {
              if (
                CONFIG.debug === true
              ) {
                console.log(error);
              };
            };

            // Validate message group member object

            if (
              typeof(messageGroupMember) !== 'object' ||
              typeof(messageGroupMember.action) !== 'string' ||
              typeof(messageGroupMember.payload) === 'undefined'
            ) {
              return;
            };

            // Handle messageGroupMember object action

            switch (
              messageGroupMember.action
            ) {

              /* ---------------
                 Ecdh public key
                 --------------- */

              case 'ecdhPublicKey':

                // messageGroupMember.payload - string - contains the group member ecdh public key

                if (
                  typeof(messageGroupMember.payload) !== 'string'
                ) {
                  break;
                };

                // Calculate the ecdh shared key from the group member ecdh public key then set aes resources

                try {

                  var sharedKey = GROUP[message.payload.member].crypt.ecdh.derive(ECDHC25519.keyFromPublic(messageGroupMember.payload, 'hex').getPublic()).toString(16);
                  sharedKey = ( sharedKey.substr(0, 32) + sharedKey.substr(-32, 32) );
                  sharedKey = xorHex(sharedKey, credentials.groupPassword);

                  GROUP[message.payload.member].crypt.aes.send = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter((
                    parseInt(message.payload.member, 16) < parseInt(connectionID, 16)
                    ? 1
                    : 2147483648
                  )));
                  GROUP[message.payload.member].crypt.aes.receive = new AES.ModeOfOperation.ctr(convertHexToBytes(sharedKey), new AES.Counter((
                    parseInt(message.payload.member, 16) < parseInt(connectionID, 16)
                    ? 2147483648
                    : 1
                  )));

                } catch ( error ) {

                  if (
                    CONFIG.debug === true
                  ) {
                    console.log(error);
                  };

                  break;

                };

                // Send username to the group member

                self.sendMessageGroupMember(message.payload.member, {
                  'action' : 'userName',
                  'payload' : credentials.userName,
                });

                break;

              /* --------
                 Username
                 -------- */

              case 'userName':

                // messageGroupMember.payload - string - contains the group member username

                if (
                  GROUP[message.payload.member].crypt.aes.send === null ||
                  GROUP[message.payload.member].crypt.aes.receive === null ||
                  typeof(messageGroupMember.payload) !== 'string'
                ) {
                  break;
                };

                // Set the group member username

                GROUP[message.payload.member].userName = messageGroupMember.payload;

                // Update group members

                var groupMembers = {};

                Object.keys(GROUP).map(function ( member, index ) {
                  if (
                    GROUP[member].userName !== null &&
                    GROUP[member].crypt.aes.send !== null &&
                    GROUP[member].crypt.aes.receive !== null
                  ) {
                    groupMembers[member] = GROUP[member].userName;
                  };
                });

                updateGroupMembers(groupMembers);

                break;

              /* -------------
                 Message group
                 ------------- */

              case 'messageGroup':

                // messageGroup.payload - string - contains the message to the group

                if (
                  GROUP[message.payload.member].crypt.aes.send === null ||
                  GROUP[message.payload.member].crypt.aes.receive === null ||
                  typeof(messageGroupMember.payload) !== 'string'
                ) {
                  break;
                };

                // Show message

                showMessage(GROUP[message.payload.member].userName, messageGroupMember.payload);

                break;

            };

            break;

        };

      };
    };

    /* --------------
       HANDLE ONERROR
       -------------- */

    this.connection.onerror = function ( event ) {
      if (
        CONFIG.debug === true
      ) {
        console.log(event);
      };
    };

    /* --------------
       HANDLE ONCLOSE
       -------------- */

    this.connection.onclose = function () {

      // Show connecting overlay

      showConnecting();

      // Reset crypt variables

      crypt = {
        'ecdh' : null,
        'aes' : {
          'send' : null,
          'receive' : null,
        },
      };

      // Reset connection id

      connectionID = null;

      // Reset group members

      GROUP = {};

      // Update connected status

      self.status.connected = false;

      // Stop sending ping requests

      clearInterval(self.sendPingRequests);

      // Reconnect to wss with a delay

      setTimeout(function () {
        self.wssConnect();
      }, CONFIG.wssReconnectDelay);

    };

  };

  /* =====================
      MESSAGING FUNCTIONS
     ===================== */

  // Send message to server

  this.sendMessage = function ( message ) {
    if (
      self.status.connected === true
    ) {

      try {

        // Encrypt message if necessary then send message object

        var data;

        if (
          crypt.aes.send !== null &&
          crypt.aes.receive !== null
        ) {
          data = convertBytesToBase64(crypt.aes.send.encrypt(convertStringToBytes(JSON.stringify(message))));
        } else {
          data = convertBytesToBase64(convertStringToBytes(JSON.stringify(message)));
        }

        self.connection.send(data);

        if (
          CONFIG.debug === true
        ) {
          console.log('SENT RAW DATA TO SERVER:');
          console.log(data);
        };

        if (
          CONFIG.debug === true
        ) {
          console.log('SENT MESSAGE OBJECT TO SERVER:');
          console.log(message);
        };

      } catch ( error ) {

        if (
          CONFIG.debug === true
        ) {
          console.log(error);
        };

        return(false);

      };

      return(true);

    } else {
      return(false);
    };
  };

  // Send message to group

  this.sendMessageGroup = function ( message ) {

    var messages = {};

    Object.keys(GROUP).map(function ( member, index ) {
      if (
        GROUP[member].userName !== null &&
        GROUP[member].crypt.aes.send !== null &&
        GROUP[member].crypt.aes.receive !== null
      ) {
        try {
          messages[member] = convertBytesToBase64(GROUP[member].crypt.aes.send.encrypt(convertStringToBytes(JSON.stringify({
            'action' : 'messageGroup',
            'payload' : message,
          }))));
        } catch ( error ) {
          if (
            CONFIG.debug === true
          ) {
            console.log(error);
          };
        };
      };
    });

    showMessage(credentials.userName, message, (
      self.sendMessage({
        'action' : 'messageGroup',
        'payload' : messages,
      }) === true
      ? Object.keys(messages).length
      : 0
    ));

  };

  // Send message to group member

  this.sendMessageGroupMember = function ( member, message ) {
    if (
      typeof(GROUP[member]) === 'object'
    ) {
      try {

        // Encrypt message if necessary then send message object

        if (
          GROUP[member].crypt.aes.send !== null &&
          GROUP[member].crypt.aes.receive !== null
        ) {
          self.sendMessage({
            'action' : 'messageGroupMember',
            'payload' : {
              'member' : member,
              'message' : convertBytesToBase64(GROUP[member].crypt.aes.send.encrypt(convertStringToBytes(JSON.stringify(message)))),
            },
          });
        } else {
          self.sendMessage({
            'action' : 'messageGroupMember',
            'payload' : {
              'member' : member,
              'message' : convertBytesToBase64(convertStringToBytes(JSON.stringify(message))),
            },
          });
        };

      } catch ( error ) {
        if (
          CONFIG.debug === true
        ) {
          console.log(error);
        };
      };
    };
  };

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

// Xor hex

function xorHex ( a, b ) {

  var result = '',
      i = a.length,
      j = b.length;

  while (
    i-- > 0 &&
    j-- > 0
  ) {
    result = ( parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16) ).toString(16) + result;
  };

  return(result);

};
