var process = require('process');
var freedom = require('freedom-for-node');
var rawFreedom = require('freedom');
var randgen = require('randgen');
var request = require('request');
var crypto = require('crypto');
var fs = require('fs');
var unused = require('json-store');
var testutil = require('freedom/spec/util');
var argv = require('yargs')
    .usage('Usage: $0 [-v] [-h] [-i] [-r N] [-g msg] [-s] <msgfile>')
    .count('verbose')
    .boolean('init')
    .boolean('save')
    .default('roleNum', 0)
    .default('init', false)
    .default('save', false)
    .alias('h', 'help')
    .alias('i', 'init')
    .alias('r', 'roleNum')
    .alias('g', 'generate')
    .alias('s', 'save')
    .alias('v', 'verbose')
    .help('help')
    .demand(1)
    .argv;

//debugger;
// Message File Format:
/*

  {

  -- returned from e2e's key generator.  To reliably reconstruct the
  -- same keys.  NO.  Instead, hard-code two hand-made keys and use
  -- them.  Otherwise this is all rather crap, fighting keys back and
  -- forth.
  keys: { password, keys: [0-key, 1-key ] }
  hashes: [ {h3, h2, h1, h0}, {h3, h2, h1, h0} ]
  hello-0: {}
  hello-1: {}
  init-role: 0 or 1
  commit: {}
  dhpart1: {}
  dhpart2: {}
  confirm1: {}
  confirm2: {}
  conf2ack: {}
  }

*/

var filename = argv._[0];
var loaded_messages = {}

var raw_key_password = '';
var raw_keys = [
  {
    'private':
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Charset: UTF-8\n' +
        'Version: End-To-End v0.31337.1\n' +
        '\n' +
        'xf8AAAB3BAAAAAATCCqGSM49AwEHAgMESZrm3yXlt+KgUzXy2gu9MWqJ5C6RNmxF\n' +
        'c0+mENdG3OId4RnR9gBNJonc7EyPz6dEpB2SafXQ0/PwrxaPMesJDAABAKLiTquo\n' +
        'xQdVoI/Zbviq2JLxbV2UlHeYEze3anX2LEMoESjN/wAAABQ8dXNlci0wQGV4YW1w\n' +
        'bGUuY29tPsL/AAAAjgQQEwgAQP8AAAAFglartE3/AAAAAosJ/wAAAAmQ7u+h7OtC\n' +
        'Cmb/AAAABZUICQoL/wAAAASWAwEC/wAAAAKbA/8AAAACngEAAIOBAP90TNLZ5e5D\n' +
        'eAnZoIt5tN8bg+TPiYJKDWOglsZSR8jnWwEAo/e6JlLPHdSyQG3nQe/jmcGvPL1I\n' +
        'AYUNC5NWm3BJUO/H/wAAAHsEAAAAABIIKoZIzj0DAQcCAwTpN0eqkzXDgrstHeSW\n' +
        '6zKIFDHhzSRDR+mqZrReUJENOvsQLJzPelauT7umBP05fkONvoga4tGY1ZdFeIkz\n' +
        'fsioAwEIBwAA/3VDQ0gISiheFRguXJn9S+0+wOQdYWkPdVaVBL0GKL/+DYPC/wAA\n' +
        'AG0EGBMIAB//AAAABYJWq7RN/wAAAAmQ7u+h7OtCCmb/AAAAApsMAADVzAEAxNKU\n' +
        'Gb3xRCsFlwGgwx07qMGrUF4Y7sh2OZASNX3sTf4BAJFguEEVhU9z+SkElXyphb+q\n' +
        'PC6719E4g9mp1nK5myCrxv8AAABSBAAAAAATCCqGSM49AwEHAgMESZrm3yXlt+Kg\n' +
        'UzXy2gu9MWqJ5C6RNmxFc0+mENdG3OId4RnR9gBNJonc7EyPz6dEpB2SafXQ0/Pw\n' +
        'rxaPMesJDM3/AAAAFDx1c2VyLTBAZXhhbXBsZS5jb20+wv8AAACOBBATCABA/wAA\n' +
        'AAWCVqu0Tf8AAAACiwn/AAAACZDu76Hs60IKZv8AAAAFlQgJCgv/AAAABJYDAQL/\n' +
        'AAAAApsD/wAAAAKeAQAAg4EA/3RM0tnl7kN4Cdmgi3m03xuD5M+JgkoNY6CWxlJH\n' +
        'yOdbAQCj97omUs8d1LJAbedB7+OZwa88vUgBhQ0Lk1abcElQ787/AAAAVgQAAAAA\n' +
        'EggqhkjOPQMBBwIDBOk3R6qTNcOCuy0d5JbrMogUMeHNJENH6apmtF5QkQ06+xAs\n' +
        'nM96Vq5Pu6YE/Tl+Q42+iBri0ZjVl0V4iTN+yKgDAQgHwv8AAABtBBgTCAAf/wAA\n' +
        'AAWCVqu0Tf8AAAAJkO7voezrQgpm/wAAAAKbDAAA1cwBALFOYLzzlUL4mVEBywUJ\n' +
        'QyI4ZVnWO5BUhDtuxSMByC5vAP9LKf7iBwfAa3R7mRIMD675PFqKdAFNiTDv5A5g\n' +
        'JxPp1Q==\n' +
        '=BvAW\n' +
        '-----END PGP PRIVATE KEY BLOCK-----\n'
 },
  {
    'private':
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Charset: UTF-8\n' +
        'Version: End-To-End v0.31337.1\n' +
        '\n' +
        'xf8AAAB3BAAAAAATCCqGSM49AwEHAgMEFBwMuJYcFZ8diyWqImSpcjIDVXvrvTqi\n' +
        '3ZW6aP2Xa7hM1RzpXNEJWf0MmSXcYPDF10t1NYGyFObi9MRGoVI1uAABAIpkPlZ0\n' +
        'ekouOO8LrzBQyBbeR8/E+BrC5/SVweBFSHeqEHPN/wAAABQ8dXNlci0xQGV4YW1w\n' +
        'bGUuY29tPsL/AAAAjgQQEwgAQP8AAAAFglartIL/AAAAAosJ/wAAAAmQXj/bCxIp\n' +
        'OcD/AAAABZUICQoL/wAAAASWAwEC/wAAAAKbA/8AAAACngEAALZtAP40gWxAFmWi\n' +
        'QtX0NcwueplZ9NGDXRmiZ/nib0YUDLISUgD/QlSj7uQMeakFNjXxRz8V1BqzyMRC\n' +
        'kxzgWJz+n5S8KuPH/wAAAHsEAAAAABIIKoZIzj0DAQcCAwS1SHoSCjjOKdpzbUN/\n' +
        'eIFRG9YdMaUUzFmDQ7UhbKZP/MNcBdACy87jVwI2tNh5rSWLhqPiEegMqTXZsqxd\n' +
        '2ki3AwEIBwAA/1iPkMsIvyzP2idPN2y+wFY/zmDG2xR8nzVNEcXnZCR9EEvC/wAA\n' +
        'AG0EGBMIAB//AAAABYJWq7SC/wAAAAmQXj/bCxIpOcD/AAAAApsMAADG6AD/RDyt\n' +
        'sJ4dQ7FNACg5kvuC8y4MhO6EsoStVZSHgFXx6z8A/3y62Mh4rdBtjstmZase21OV\n' +
        'Bzyi7hW5y4rRJHRSg1bJxv8AAABSBAAAAAATCCqGSM49AwEHAgMEFBwMuJYcFZ8d\n' +
        'iyWqImSpcjIDVXvrvTqi3ZW6aP2Xa7hM1RzpXNEJWf0MmSXcYPDF10t1NYGyFObi\n' +
        '9MRGoVI1uM3/AAAAFDx1c2VyLTFAZXhhbXBsZS5jb20+wv8AAACOBBATCABA/wAA\n' +
        'AAWCVqu0gv8AAAACiwn/AAAACZBeP9sLEik5wP8AAAAFlQgJCgv/AAAABJYDAQL/\n' +
        'AAAAApsD/wAAAAKeAQAAtm0A/jSBbEAWZaJC1fQ1zC56mVn00YNdGaJn+eJvRhQM\n' +
        'shJSAP9CVKPu5Ax5qQU2NfFHPxXUGrPIxEKTHOBYnP6flLwq487/AAAAVgQAAAAA\n' +
        'EggqhkjOPQMBBwIDBLVIehIKOM4p2nNtQ394gVEb1h0xpRTMWYNDtSFspk/8w1wF\n' +
        '0ALLzuNXAja02HmtJYuGo+IR6AypNdmyrF3aSLcDAQgHwv8AAABtBBgTCAAf/wAA\n' +
        'AAWCVqu0gv8AAAAJkF4/2wsSKTnA/wAAAAKbDAAAxugBAMXSmje/LKMk1EyIrn4+\n' +
        'xcwKRzUiuDeg1EKsUWGcIVwcAPoCJlH/uaVStEdVDaLRqgvhYzUJOMWZgBz1Vn7I\n' +
        'JmFLrg==\n' +
        '=UvKo\n' +
        '-----END PGP PRIVATE KEY BLOCK-----\n'
  }
];

var alice, bob;
var seqno = 1;

function LogFailureAndExit(err) {
  console.log('LogFailure!');
  console.log(err);
}

// Hash/Nonce generation
function generateNonceAndHashes() {
  var h0Hash = crypto.createHash('sha256'),
      h1Hash = crypto.createHash('sha256'),
      h2Hash = crypto.createHash('sha256'),
      h3Hash = crypto.createHash('sha256');
  h0Hash.update(new Date().toISOString() + '--' + seqno);
  seqno++;
  var h0 = h0Hash.digest();
  h1Hash.update(h0);
  var h1 = h1Hash.digest();
  h2Hash.update(h1);
  var h2 = h2Hash.digest();
  h3Hash.update(h2);
  var h3 = h3Hash.digest();
  return [h3.toString('base64'), h2.toString('base64'),
          h1.toString('base64'), h0.toString('base64')];
}


// modifies destination: xor's each byte in 'buf' with 'value'.
function xorBuffer(buf, value) {
  for (var i = 0; i < buf.length; i++) {
    buf.writeInt8(buf.readInt8(i) ^ (+value), i);
  }
  return buf;
}

function strBuffer(buf) {
  var b = new DataView(buf);
  var result = "";
  for (var i = 0; i < b.byteLength; i++) {
    if (i != 0) {
      result += ",";
    }
    result += b.getUint8(i);
  }
  return result;
}

function strNBuffer(b) {
  if (Buffer.isBuffer(b)) {
    var result = "";
    for (var i = 0; i < b.length; i++) {
      if (i != 0) {
        result += ",";
      }
      result += b.readUInt8(i);
    }
    return result;
  } else {
    return "not a node buffer.";
  }
}


// Assumes key and value are base64-encoded strings.
function fullHmac(key, value) {
  var kBlockSize = 64;  // sha-256 block size is 512 bits - 64 bytes.
  var key_buf = new Buffer(key, 'base64');
  if (argv.verbose > 0) {
    console.log("fullHmac: key: ", key);
    console.log("fullHmac: value: ", value);
  }
  // Follow FIPS-198 quite literally.  I haven't found any docs on
  // createHmac(sha256,key) w.r.t. FIPS-198.
  if (key_buf.length > kBlockSize) {
    var hmac = crypto.createHash('sha256');
    hmac.update(key_buf);
    var hash_key = hmac.digest();
    key_buf = Buffer.concat([hmac.digest(),
                             new Buffer(key_buf.length - kBlockSize).fill(0)],
                            kBlockSize);
  } else if (key_buf.length < kBlockSize) {
    key_buf = Buffer.concat([key_buf, new Buffer(kBlockSize - key_buf.length).fill(0)],
                            kBlockSize);
  }

  var k_0 = new Buffer(key_buf);
  if (argv.verbose > 0) {
    console.log('fullHmac k_0:', strNBuffer(k_0));
  }
  // ipad = 0x36.
  var kb_step4 = xorBuffer(new Buffer(k_0), 0x36);
  if (argv.verbose > 0) {
    console.log('fullHmac A:',strNBuffer(kb_step4));
  }
  // Step 5
  var ki_text = Buffer.concat([kb_step4, new Buffer(value, 'base64')]);
  if (argv.verbose > 0) {
    console.log('fullHmac B:',strNBuffer(ki_text));
  }

  // Step 6
  var h_ki_text = crypto.createHash('sha256').update(ki_text).digest();
  if (argv.verbose > 0) {
    console.log('fullHmac C:',h_ki_text);
  }

  // Step 7 - xor with 0x5c.
  var ko_text = xorBuffer(new Buffer(k_0), 0x5c);
  if (argv.verbose > 0) {
    console.log('fullHmac D:',strNBuffer(ko_text));
  }

  // Step 8 - concat steps 7 and 6
  var ki_h_ko_text = Buffer.concat([ko_text, h_ki_text]);
  if (argv.verbose > 0) {
    console.log('fullHmac E:',strNBuffer(ki_h_ko_text));
  }

  // Final step: hash step 8.
  var full_hmac = crypto.createHash('sha256').update(ki_h_ko_text).digest();
  if (argv.verbose > 0) {
    console.log('fullHmac F:',full_hmac);
  }

  return full_hmac;
}

// http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
// Assumes key and value are base64-encoded strings.  Returns a base64-encoded
// 16 bit number as a string.
function mac(key, value){
  var full_hmac = fullHmac(key, value);
  // Two bytes -> 16 bits of mac.
  var result = new Buffer(full_hmac.slice(0, 2)).toString('base64');
//  console.log('MAC('+key+','+value+') RESULT: ' +result);
  return result;
}

// Load key(s)
function SearchAlicesKey(param) {
//  console.log('SearchAlicesKey: running with param ', param);
  alice.searchPrivateKey('<user-0@example.com>').addCallback(
      function(v) {
        //console.log('searchPrivateKey: Success', v);
      })
  .addErrback(function(err) {
    console.log('searchaliceskey: failed:', err);
  });
}
function LoadAlicesKey() {
  console.log('Loading Alice\'s Key');
  alice.importKeypair(loaded_messages.keys.password,
                      '<user-0@example.com>',
                      loaded_messages.keys.keys[0].private)
                          .then(LoadBobsKey, LogFailureAndExit);

}


function LoadBobsKey() {
  console.log('Loading Bob\'s Key');
  bob.importKeypair(loaded_messages.keys.password,
                    '<user-1@example.com>',
                    loaded_messages.keys.keys[1].private).then(GenMessages, LogFailureAndExit);
}

function finishWithGeneratedMessage(key, value) {
//  console.log("finishWithGeneratedMessage: ", key," and value ", value);
  loaded_messages[key] = value;
  if (argv.verbose > 0) {
    console.log('Generated: ' + key + ': ' + JSON.stringify(value, null, 2));
  }
  if (argv.save) {
    if (argv.verbose > 0) {
      console.log("Saving to " + filename);
    }
    fs.writeFileSync(filename, JSON.stringify(loaded_messages));
  }
  process.exit(0);
}

function makeHello(own_public_key, role) {
  var message = {type: 'Hello', clientVersion: '0.1'};
  message.h3 = loaded_messages.hashes[role][0];
  message.hk = own_public_key.fingerprint.replace(/ /g, '');
  message.mac = mac(loaded_messages.hashes[role][1],
                    message.h3 + message.hk + message.clientVersion);
  return message;
}

function makeDHPart(partNr, own_public_key, role) {
  var message = {type: 'DHPart' + partNr };
  message.h1 = loaded_messages.hashes[role][2];
  message.pkey = own_public_key.key;
  message.mac = mac(loaded_messages.hashes[role][3], message.h1 + message.pkey);
  return message;
}

function totalHash(role) {
  var hello_r;
  if (loaded_messages['init-role'] == 0) {
    hello_r = loaded_messages['hello-1'];
  } else {
    hello_r = loaded_messages['hello-0'];
  }
  var commit = loaded_messages.commit;
  var dhpart1 = loaded_messages.dhpart1;
  var dhpart2 = loaded_messages.dhpart2;
  var total_hash_buf = Buffer.concat([
    new Buffer(hello_r.h3), new Buffer(hello_r.hk), new Buffer(hello_r.mac),
    new Buffer(commit.h2), new Buffer(commit.hk), new Buffer(commit.clientVersion),
    new Buffer(commit.hvi),
    new Buffer(dhpart1.h1), new Buffer(dhpart1.pkey), new Buffer(dhpart1.mac),
    new Buffer(dhpart2.h1), new Buffer(dhpart2.pkey), new Buffer(dhpart2.mac)
  ]);

  if (argv.verbose > 0) {
    console.log("totalHash: init-role: ", loaded_messages['init-role']);
    console.log("totalHash: hello_r: h3:", hello_r.h3, ", hk:", hello_r.hk, ", mac:", hello_r.mac);
    console.log("totalHash: commit: h2: ", commit.h2, ", hk:", commit.hk, ", clientVersion:",
                commit.clientVersion, ", hvi:", commit.hvi);
    console.log("totalHash: dhpart1: h1:", dhpart1.h1, ", pkey:", dhpart1.pkey, ", mac:", dhpart1.mac);
    console.log("totalHash: dhpart2: h1:", dhpart2.h1, ", pkey:", dhpart2.pkey, ", mac:", dhpart2.mac);
  }

  var hashed = crypto.createHash('sha256').update(total_hash_buf).digest();
  return hashed;
}
// 'key' is a regular buffer, that we re-encode into a base64 string for fullHmac.
function kdf(key, label, context, numbits) {
  var oneBuf = new Buffer(4);
  var lenBuf = new Buffer(4);
  oneBuf.writeInt32BE(1, 0);
  lenBuf.writeInt32BE(numbits, 0);
  if (argv.verbose > 0) {
    console.log("kdf: key", key);
    console.log("kdf: oneBuf", oneBuf);
    console.log("kdf: label", new Buffer(label));
    console.log("kdf: context", new Buffer(context));
    console.log("kdf: lenBuf", lenBuf);
  }
  var b64Key = key.toString('base64');
  var zeroByte = new Buffer(1);
  zeroByte.writeUInt8(0,0);
  var completeValue = Buffer.concat([
    oneBuf, new Buffer(label), zeroByte, new Buffer(context), lenBuf]);
  var full_hmac = fullHmac(b64Key, completeValue.toString('base64'));
  if (argv.verbose > 0) {
    console.log("kdf: full_hmac: ", full_hmac);
  }
  return full_hmac.slice(0, Math.ceil(numbits / 8));
}

// Generate Message(s)
function GenMessages() {
//  console.log("Starting GenMessages.");
  // Look at what message the arg asked for:
  if (argv.generate) {
    var desired_message = argv.generate.toLowerCase();
    var role_user = (argv.roleNum === 0) ? alice : bob;
    var other_user = (argv.roleNum === 0) ? bob : alice;
    var keys = [null, null];
    console.log('Generating messages:' + argv.generate + ', ('+desired_message+')');
    role_user.exportKey().then(function (own_public_key) {
      keys[argv.roleNum] = own_public_key;
      if (desired_message == 'hello') {
        if (argv.verbose > 0) {
          console.log('- Got own_public_key: ' + JSON.stringify(own_public_key, null, 2));
        }
        var message = makeHello(own_public_key, argv.roleNum);
        finishWithGeneratedMessage('hello-' + argv.roleNum, message);
      } else // commit requires dhpart1/2, so make them.
        if (desired_message == 'commit') {
          // The role_user (argv.roleNum) is the initiator.
          var initiator, responder;
          initiator = argv.roleNum;
          responder = initiator ^ 1;
          if (!loaded_messages.hasOwnProperty('dhpart2')) {
            loaded_messages.dhpart2 = makeDHPart(2, own_public_key, argv.roleNum);
          }
          if (!loaded_messages.hasOwnProperty('hello-'+responder)) {
              console.log('xx Need to generate HELLO messages before COMMIT.');
              process.exit(1);
          }
          var dhpart2 = loaded_messages.dhpart2.h1 + loaded_messages.pkey + loaded_messages.mac;
          var hello_obj = loaded_messages['hello-' + responder];
          var hello = hello_obj.h3 + hello_obj.hk + hello_obj.mac;
          var hvi = crypto.createHash('sha256').update(dhpart2 + hello).digest('base64');
          var h2 = loaded_messages.hashes[argv.roleNum][2];
          var hk = crypto.createHash('sha256').update(own_public_key.key).digest('base64');
          var version = '0.1';
          var message = {
            'type': 'Commit',
            'clientVersion': version,
            'h2': h2,
            'hk': hk,
            'hvi':hvi,
            mac: mac(loaded_messages.hashes[argv.roleNum][1],h2+hk+version+hvi)
          };
          loaded_messages['init-role'] = argv.roleNum;
          finishWithGeneratedMessage('commit', message);
        } else if (desired_message == 'confirm') {
          if (!loaded_messages.hasOwnProperty('init-role')) {
            console.log('FAILURE: Cannot confirm an uninitiated session.');
            process.exit(1);
          }
          var init_role = parseInt(loaded_messages['init-role']);
          var initiator_user = (init_role === 0)? alice : bob;
          var responding_user = (init_role === 0)? bob : alice;

          other_user.exportKey().then(function (other_public_key) {
            keys[argv.roleNum ^ 1] = other_public_key;
            // These are public keys.
            var init_key = keys[init_role];
            var resp_key = keys[init_role ^ 1];
            if (!loaded_messages.hasOwnProperty('dhpart1')) {
              loaded_messages.dhpart1 = makeDHPart(1, resp_key,
                                                  parseInt(loaded_messages['init-role']) ^ 1);
            }
            // first, calculate s0 by doing the DH exchange math.  Note that
            // this is a little confusing in that initiator_user may be either
            // alice or bob.  So let's ignore the fact that the api is called
            // ecdhBob, as that's not related specifically to our alice or bob.
            // It's the bob role, not our actual bob.
            initiator_user.ecdhBob('P_256', resp_key.key).then(function (result) {
              var be64Zero = new Buffer(8),
                  beZero = new Buffer(4),
                  beOne = new Buffer(4);
              beOne.writeInt32BE(1,0);
              beZero.writeInt32BE(0,0);
              be64Zero.writeInt32BE(0,0);
              be64Zero.writeInt32BE(0,4);
              // RFC6189-4.4.1.4
              var total_hash = totalHash();
              var s0_input = Buffer.concat([
                beOne, new Buffer(result), new Buffer("ZRTP-HMAC-KDF"), be64Zero,
                be64Zero, total_hash, beZero, beZero, beZero]);
              if (argv.verbose > 0) {
                console.log("s0_inputs: result:", strBuffer(result));
                console.log("s0_inputs: total_hash:", total_hash);
                console.log("so_inputs: beOne:", beOne);
                console.log("so_inputs: be64Zero:", be64Zero);
                console.log("so_inputs: beZero:", beZero);
              }
              var s0 = crypto.createHash('sha256').update(s0_input).digest();
              if (argv.verbose > 0) {
                console.log("s0: ", s0);
              }
              var kdf_context = Buffer.concat([ be64Zero, be64Zero, total_hash ]);
              if (argv.verbose > 0) {
                console.log("kdf_context: ", kdf_context);
              }
              // RFC6189-4.5.2
              var sashash = kdf(s0, "SAS", kdf_context, 256);
              if (argv.verbose > 0) {
                console.log("sashash: ", sashash);
              }
              var sasvalue = sashash.slice(0, 4);
              if (argv.verbose > 0) {
                console.log("sasvalue: ", sasvalue);
              }
              var sasHumanInt = sasvalue.slice(0,2).readUInt16BE(0);
              console.log("SAS is " + sasHumanInt);
              var h0 = loaded_messages.hashes[argv.roleNum][3]
              var message = {
                'type': 'Confirm' + ((init_role === argv.roleNum) ? '2' : '1'),
                'mac': mac(s0.toString('base64'), h0),
                'h0': h0
              };
              finishWithGeneratedMessage(message.type, message);
            });
          });
        } else {
          console.log("Unknown message type: ", desired_message);
          process.exit(0);
        }
    }, LogFailureAndExit);
  } else {
    console.log("Not generating messages.  Exiting.");
    process.exit(0);
  }
}

//var pgpapi = JSON.parse(fs.readFileSync('node_modules/freedom-pgp-e2e/dist/pgpapi.json', 'utf8')).api.crypto;
//var e2e = require('freedom-pgp-e2e/dist/e2e_super').mye2e;
//var proto = testutil.directProviderFor(e2e, pgpapi);

freedom.freedom('node_modules/freedom-pgp-e2e/dist/pgpapi.json', {
//  portType: 'Direct', moduleContext: true
}).then(
    function(proto) {
      alice = new proto();
      bob = new proto();
      // Define a JSON blob for the conversation.  We can only
      // generate messages that we have dependencies for.
      if (argv.init) {
        // Generate keys, nonces, and hashes for both.
        loaded_messages['keys'] = { 'password': raw_key_password,
                                    'keys': raw_keys };
        loaded_messages['hashes'] = [generateNonceAndHashes(),
                                     generateNonceAndHashes()];
        console.log("Saving to " + filename);
        fs.writeFileSync(filename, JSON.stringify(loaded_messages));
      } else {
        console.log("Reading from " + filename);
        loaded_messages = JSON.parse(fs.readFileSync(filename, 'utf8'));
        if (argv.verbose > 0) {
          console.log('Loaded: ' + JSON.stringify(loaded_messages, null, 2));
        }
      }
      // Kickstart the process by loading alice's key.
      LoadAlicesKey();
    }
);
