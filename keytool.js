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

var raw_key_password = 'password';
var raw_keys = [
  {
    "private": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "Version: GnuPG v2\n" +
        "\n" +
        "lKUEVqKVaRMIKoZIzj0DAQcCAwQj1vXJdzlfHhiXV5s0d9HK5q6edPgG9+uQVqYX\n" +
        "/aJy/BWbSDKfX8IHmKRhfB6Msg8XFxq3UbaeVuZNtgEifURX/gcDArDnmWfqHUtt\n" +
        "4jWQBri84gK6IMzvE/8TX902ntKCKqj/i2SgP85dzxFiAaaiWgupiQKJ33CygK4d\n" +
        "sf2rRnv771jceuVLSv1G8Jzny13Zx/+0G3VzZXItMCA8dXNlci0wQGV4YW1wbGUu\n" +
        "Y29tPoh5BBMTCAAhBQJWopVpAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ\n" +
        "EPcjztauAk2VBnQA/1fZHalPbVxALq09Yq7FNzghakHgoyEkwekbQ+KNGAeCAPsG\n" +
        "Hsd2asFC70XAnYADKJGxtKebNmHfWVyA6AjGJyFB75ypBFailWkSCCqGSM49AwEH\n" +
        "AgMEQqgnUFOXnwI6OMJnaIVtXl4c3OgdInRgUfjpT//PFhYz2FPqt4c/1pHYhzx/\n" +
        "6QqggObexKdY+dRZFS0DgL44MQMBCAf+BwMCB773+rJ/ncviTheSXe6VTgboxrTd\n" +
        "gKiQhCOAcByz/2cUUdyeeJ1p2qyzwNK1+8oWWiuGpbIS+FCpwTZO/ChqiVQed4i5\n" +
        "eD6IITRDuhaO5YhhBBgTCAAJBQJWopVpAhsMAAoJEPcjztauAk2VJQAA/18vW/TV\n" +
        "ZJTTD8JuOvtzNWConrcH/BzSUhgHTgLgr5DQAQD33WqSY/Jodb0hvu9+rl1kK35u\n" +
        "qqr9UVQ3ueoCthcknA==\n" +
        "=UuAm\n" +
        "-----END PGP PRIVATE KEY BLOCK-----",
    "public": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "Version: GnuPG v2\n" +
        "\n" +
        "mFIEVqKVaRMIKoZIzj0DAQcCAwQj1vXJdzlfHhiXV5s0d9HK5q6edPgG9+uQVqYX\n" +
        "/aJy/BWbSDKfX8IHmKRhfB6Msg8XFxq3UbaeVuZNtgEifURXtBt1c2VyLTAgPHVz\n" +
        "ZXItMEBleGFtcGxlLmNvbT6IeQQTEwgAIQUCVqKVaQIbAwULCQgHAgYVCAkKCwIE\n" +
        "FgIDAQIeAQIXgAAKCRD3I87WrgJNlQZ0AP9X2R2pT21cQC6tPWKuxTc4IWpB4KMh\n" +
        "JMHpG0PijRgHggD7Bh7HdmrBQu9FwJ2AAyiRsbSnmzZh31lcgOgIxichQe+4VgRW\n" +
        "opVpEggqhkjOPQMBBwIDBEKoJ1BTl58COjjCZ2iFbV5eHNzoHSJ0YFH46U//zxYW\n" +
        "M9hT6reHP9aR2Ic8f+kKoIDm3sSnWPnUWRUtA4C+ODEDAQgHiGEEGBMIAAkFAlai\n" +
        "lWkCGwwACgkQ9yPO1q4CTZUlAAD/Xy9b9NVklNMPwm46+3M1YKietwf8HNJSGAdO\n" +
        "AuCvkNABAPfdapJj8mh1vSG+736uXWQrfm6qqv1RVDe56gK2FySc\n" +
        "=vXCi\n" +
        "-----END PGP PUBLIC KEY BLOCK-----"
  },
  {
    "private": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "Version: GnuPG v2\n" +
        "\n" +
        "lKUEVqKhlBMIKoZIzj0DAQcCAwTxOl087JaSP14G1sHGacKOJkgaVnpOgc0PVQle\n" +
        "kpv7bAWEEm4qy0l+LQuACFnf1f0WJLlsRpyoiJrHuseqT2Jn/gcDAsHo7L1c5nII\n" +
        "4t0GZCtNhhzD+jFlKy5uJ5GBc3qeHJw8/lO57KBbftP8toqyhXlwdHSuaH5ykTDT\n" +
        "mr1ZituwCdD9LMAhJy/7T+JPlDcCdYS0G3VzZXItMSA8dXNlci0xQGV4YW1wbGUu\n" +
        "Y29tPoh5BBMTCAAhBQJWoqGUAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ\n" +
        "ENVWGTIGMA5gU4wBALgTYRO/XCGF1zewnoBdXRU1OX3bAx3n7JV5Eor528TbAQCb\n" +
        "qyLw2E6Ybpe6qfFpQWYoNS120eiuA1ajCQAyT8sbCpypBFaioZQSCCqGSM49AwEH\n" +
        "AgMEYosxhZvy06PqgnfhmqCQ++VmdWqEc6b98HcfcdVXYiZBzL5ctmpPjzdKDKa9\n" +
        "bPtVHEOaE0xsTjabf8YKiQ/75gMBCAf+BwMCTVAg716V2PjiezwFE45Z24HhqXMf\n" +
        "wzoMWooWxihQbGNLlbjnrXGTLfm2RStcaa7rZ6J+VeSgQUs7Y1GCjU7gccMFAif6\n" +
        "QRr93tLJ1q8rrohhBBgTCAAJBQJWoqGUAhsMAAoJENVWGTIGMA5gj6cBAJXHQVHH\n" +
        "cYmpvO3Z5cZCMVJWKUOvPCv3o10QBOrcRH0RAP4gw+7nQqsZw+hBOovNmMgiJJM+\n" +
        "Kc2gXqqYhoFBiSqZDQ==\n" +
        "=WcnX\n" +
        "-----END PGP PRIVATE KEY BLOCK-----",
    "public": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "Version: GnuPG v2\n" +
        "\n" +
        "mFIEVqKhlBMIKoZIzj0DAQcCAwTxOl087JaSP14G1sHGacKOJkgaVnpOgc0PVQle\n" +
        "kpv7bAWEEm4qy0l+LQuACFnf1f0WJLlsRpyoiJrHuseqT2JntBt1c2VyLTEgPHVz\n" +
        "ZXItMUBleGFtcGxlLmNvbT6IeQQTEwgAIQUCVqKhlAIbAwULCQgHAgYVCAkKCwIE\n" +
        "FgIDAQIeAQIXgAAKCRDVVhkyBjAOYFOMAQC4E2ETv1whhdc3sJ6AXV0VNTl92wMd\n" +
        "5+yVeRKK+dvE2wEAm6si8NhOmG6XuqnxaUFmKDUtdtHorgNWowkAMk/LGwq4VgRW\n" +
        "oqGUEggqhkjOPQMBBwIDBGKLMYWb8tOj6oJ34ZqgkPvlZnVqhHOm/fB3H3HVV2Im\n" +
        "Qcy+XLZqT483SgymvWz7VRxDmhNMbE42m3/GCokP++YDAQgHiGEEGBMIAAkFAlai\n" +
        "oZQCGwwACgkQ1VYZMgYwDmCPpwEAlcdBUcdxiam87dnlxkIxUlYpQ688K/ejXRAE\n" +
        "6txEfREA/iDD7udCqxnD6EE6i82YyCIkkz4pzaBeqpiGgUGJKpkN\n" +
        "=eghU\n" +
        "-----END PGP PUBLIC KEY BLOCK-----"
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
function SearchAlicesKey() {
  console.log("SearchAlicesKey: running");
  alice.searchPrivateKey("user-0@example.com").then(
      function(v) {
        console.log("searchPrivateKey: Success", v);
      },
      LogFailureAndExit);
}
function LoadAlicesKey() {
  console.log("Loading Alice's Key");
  alice.importKeypair(loaded_messages.keys.password,
                      "user-0@example.com",
                      loaded_messages.keys.keys[0].private).then(
                          SearchAlicesKey,
                          SearchAlicesKey);
}


function LoadBobsKey() {
  console.log("Loading Bob's Key");
  bob.importKeypair(loaded_messages.keys.password,
                    "user-1@example.com",
                    loaded_messages.keys.keys[1].private).then(
                        GenMessages,
                        LogFailureAndExit
                        );
}

// Generate Message(s)
function GenMessages() {
  console.log("Generating messages.");
}

freedom.freedom('node_modules/freedom-pgp-e2e/dist/pgpapi.json', {}).then(
    function(proto) {
      alice = new proto();
      bob = new proto();
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
