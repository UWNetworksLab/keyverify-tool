var process = require("process");
var freedom = require("freedom-for-node");
var randgen = require('randgen');
var request = require('request');
var crypto = require('crypto');
var fs = require('fs');
var argv = require('yargs')
    .usage('Usage: $0 [-h] [-i] [-r N] [-g msg] [-s] <msgfile>')
    .count('init')
    .default('roleNum', 0)
    .default('init', false)
    .default('save', false)
    .alias('h', 'help')
    .alias('i', 'init')
    .alias('r', 'roleNum')
    .alias('g', 'generate')
    .alias('s', 'save')
    .help('help')
    .demand(1)
    .argv;

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
    "private":
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "Charset: UTF-8\n" +
        "Version: End-To-End v0.31337.1\n" +
        "\n" +
        "xf8AAAB3BAAAAAATCCqGSM49AwEHAgMESZrm3yXlt+KgUzXy2gu9MWqJ5C6RNmxF\n" +
        "c0+mENdG3OId4RnR9gBNJonc7EyPz6dEpB2SafXQ0/PwrxaPMesJDAABAKLiTquo\n" +
        "xQdVoI/Zbviq2JLxbV2UlHeYEze3anX2LEMoESjN/wAAABQ8dXNlci0wQGV4YW1w\n" +
        "bGUuY29tPsL/AAAAjgQQEwgAQP8AAAAFglartE3/AAAAAosJ/wAAAAmQ7u+h7OtC\n" +
        "Cmb/AAAABZUICQoL/wAAAASWAwEC/wAAAAKbA/8AAAACngEAAIOBAP90TNLZ5e5D\n" +
        "eAnZoIt5tN8bg+TPiYJKDWOglsZSR8jnWwEAo/e6JlLPHdSyQG3nQe/jmcGvPL1I\n" +
        "AYUNC5NWm3BJUO/H/wAAAHsEAAAAABIIKoZIzj0DAQcCAwTpN0eqkzXDgrstHeSW\n" +
        "6zKIFDHhzSRDR+mqZrReUJENOvsQLJzPelauT7umBP05fkONvoga4tGY1ZdFeIkz\n" +
        "fsioAwEIBwAA/3VDQ0gISiheFRguXJn9S+0+wOQdYWkPdVaVBL0GKL/+DYPC/wAA\n" +
        "AG0EGBMIAB//AAAABYJWq7RN/wAAAAmQ7u+h7OtCCmb/AAAAApsMAADVzAEAxNKU\n" +
        "Gb3xRCsFlwGgwx07qMGrUF4Y7sh2OZASNX3sTf4BAJFguEEVhU9z+SkElXyphb+q\n" +
        "PC6719E4g9mp1nK5myCrxv8AAABSBAAAAAATCCqGSM49AwEHAgMESZrm3yXlt+Kg\n" +
        "UzXy2gu9MWqJ5C6RNmxFc0+mENdG3OId4RnR9gBNJonc7EyPz6dEpB2SafXQ0/Pw\n" +
        "rxaPMesJDM3/AAAAFDx1c2VyLTBAZXhhbXBsZS5jb20+wv8AAACOBBATCABA/wAA\n" +
        "AAWCVqu0Tf8AAAACiwn/AAAACZDu76Hs60IKZv8AAAAFlQgJCgv/AAAABJYDAQL/\n" +
        "AAAAApsD/wAAAAKeAQAAg4EA/3RM0tnl7kN4Cdmgi3m03xuD5M+JgkoNY6CWxlJH\n" +
        "yOdbAQCj97omUs8d1LJAbedB7+OZwa88vUgBhQ0Lk1abcElQ787/AAAAVgQAAAAA\n" +
        "EggqhkjOPQMBBwIDBOk3R6qTNcOCuy0d5JbrMogUMeHNJENH6apmtF5QkQ06+xAs\n" +
        "nM96Vq5Pu6YE/Tl+Q42+iBri0ZjVl0V4iTN+yKgDAQgHwv8AAABtBBgTCAAf/wAA\n" +
        "AAWCVqu0Tf8AAAAJkO7voezrQgpm/wAAAAKbDAAA1cwBALFOYLzzlUL4mVEBywUJ\n" +
        "QyI4ZVnWO5BUhDtuxSMByC5vAP9LKf7iBwfAa3R7mRIMD675PFqKdAFNiTDv5A5g\n" +
        "JxPp1Q==\n" +
        "=BvAW\n" +
        "-----END PGP PRIVATE KEY BLOCK-----\n"
 },
  {
    "private":
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "Charset: UTF-8\n" +
        "Version: End-To-End v0.31337.1\n" +
        "\n" +
        "xf8AAAB3BAAAAAATCCqGSM49AwEHAgMEFBwMuJYcFZ8diyWqImSpcjIDVXvrvTqi\n" +
        "3ZW6aP2Xa7hM1RzpXNEJWf0MmSXcYPDF10t1NYGyFObi9MRGoVI1uAABAIpkPlZ0\n" +
        "ekouOO8LrzBQyBbeR8/E+BrC5/SVweBFSHeqEHPN/wAAABQ8dXNlci0xQGV4YW1w\n" +
        "bGUuY29tPsL/AAAAjgQQEwgAQP8AAAAFglartIL/AAAAAosJ/wAAAAmQXj/bCxIp\n" +
        "OcD/AAAABZUICQoL/wAAAASWAwEC/wAAAAKbA/8AAAACngEAALZtAP40gWxAFmWi\n" +
        "QtX0NcwueplZ9NGDXRmiZ/nib0YUDLISUgD/QlSj7uQMeakFNjXxRz8V1BqzyMRC\n" +
        "kxzgWJz+n5S8KuPH/wAAAHsEAAAAABIIKoZIzj0DAQcCAwS1SHoSCjjOKdpzbUN/\n" +
        "eIFRG9YdMaUUzFmDQ7UhbKZP/MNcBdACy87jVwI2tNh5rSWLhqPiEegMqTXZsqxd\n" +
        "2ki3AwEIBwAA/1iPkMsIvyzP2idPN2y+wFY/zmDG2xR8nzVNEcXnZCR9EEvC/wAA\n" +
        "AG0EGBMIAB//AAAABYJWq7SC/wAAAAmQXj/bCxIpOcD/AAAAApsMAADG6AD/RDyt\n" +
        "sJ4dQ7FNACg5kvuC8y4MhO6EsoStVZSHgFXx6z8A/3y62Mh4rdBtjstmZase21OV\n" +
        "Bzyi7hW5y4rRJHRSg1bJxv8AAABSBAAAAAATCCqGSM49AwEHAgMEFBwMuJYcFZ8d\n" +
        "iyWqImSpcjIDVXvrvTqi3ZW6aP2Xa7hM1RzpXNEJWf0MmSXcYPDF10t1NYGyFObi\n" +
        "9MRGoVI1uM3/AAAAFDx1c2VyLTFAZXhhbXBsZS5jb20+wv8AAACOBBATCABA/wAA\n" +
        "AAWCVqu0gv8AAAACiwn/AAAACZBeP9sLEik5wP8AAAAFlQgJCgv/AAAABJYDAQL/\n" +
        "AAAAApsD/wAAAAKeAQAAtm0A/jSBbEAWZaJC1fQ1zC56mVn00YNdGaJn+eJvRhQM\n" +
        "shJSAP9CVKPu5Ax5qQU2NfFHPxXUGrPIxEKTHOBYnP6flLwq487/AAAAVgQAAAAA\n" +
        "EggqhkjOPQMBBwIDBLVIehIKOM4p2nNtQ394gVEb1h0xpRTMWYNDtSFspk/8w1wF\n" +
        "0ALLzuNXAja02HmtJYuGo+IR6AypNdmyrF3aSLcDAQgHwv8AAABtBBgTCAAf/wAA\n" +
        "AAWCVqu0gv8AAAAJkF4/2wsSKTnA/wAAAAKbDAAAxugBAMXSmje/LKMk1EyIrn4+\n" +
        "xcwKRzUiuDeg1EKsUWGcIVwcAPoCJlH/uaVStEdVDaLRqgvhYzUJOMWZgBz1Vn7I\n" +
        "JmFLrg==\n" +
        "=UvKo\n" +
        "-----END PGP PRIVATE KEY BLOCK-----\n"
  }
];

var alice, bob;
var seqno = 1;

function LogFailureAndExit(err) {
  console.log("LogFailure!");
  console.log(err);
}

// Hash/Nonce generation
function generateNonceAndHashes() {
  var h0Hash = crypto.createHash('sha256'),
      h1Hash = crypto.createHash('sha256'),
      h2Hash = crypto.createHash('sha256'),
      h3Hash = crypto.createHash('sha256');
  h0Hash.update(new Date().toISOString() + "--" + seqno);
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

// Load key(s)
function SearchAlicesKey(param) {
  console.log("SearchAlicesKey: running with param ", param);
  alice.searchPrivateKey("<user-0@example.com>").addCallback(
      function(v) {
        console.log("searchPrivateKey: Success", v);
      })
  .addErrback(function(err) {
    console.log("searchaliceskey: failed:", err);
  });
}
function LoadAlicesKey() {
  console.log("Loading Alice's Key");
  alice.importKeypair(loaded_messages.keys.password,
                      "<user-0@example.com>",
                      loaded_messages.keys.keys[0].private)
                          .then(LoadBobsKey, LogFailureAndExit);

}


function LoadBobsKey() {
  console.log("Loading Bob's Key");
  bob.importKeypair(loaded_messages.keys.password,
                    "<user-1@example.com>",
                    loaded_messages.keys.keys[1].private).then(GenMessages, LogFailureAndExit);
}

// Generate Message(s)
function GenMessages() {
  console.log("Generating messages.");
  process.exit(0);
}

freedom.freedom('node_modules/freedom-pgp-e2e/dist/pgpapi.json', {}).then(
    function(proto) {
      alice = new proto();
      bob = new proto();
//      alice.setup('', "user-0@example.com");
//      bob.setup('', "user-1@example.com");
      // Define a JSON blob for the conversation.  We can only
      // generate messages that we have dependencies for.
      if (argv.init) {
        // Generate keys, nonces, and hashes for both.
        loaded_messages["keys"] = { "password": raw_key_password,
                                    "keys": raw_keys };
        loaded_messages["hashes"] = [generateNonceAndHashes(),
                                     generateNonceAndHashes()];
        fs.writeFileSync(filename, JSON.stringify(loaded_messages));
      } else {
        loaded_messages = require(filename);
      }
      // Kickstart the process by loading alice's key.
      LoadAlicesKey();
    });
