var process = require("process");
var freedom = require("freedom-for-node");
var randgen = require('randgen');
var request = require('request');
var fs = require('fs');
var argv = require('yargs')
    .usage('Usage: $0 [-h] [-i] [-r N] [-g msg] [-s] <msgfile>')
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
  -- returned from e2e's key generator.  To reliably reconstruct the same keys.
  keygen: {}
  keys: [ 0-key, 1-key ]
  hashes: [ {h0, h1, h2, h3}, {h0, h1, h2, h3} ]
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
var pgp_proto;
var loaded_messages = {}

freedom.freedom('node_modules/freedom-pgp-e2e/pgpapi.json', {}).then(
    function(proto) {
        pgp_proto = proto;
        // Define a JSON blob for the conversation.  We can only
        // generate messages that we have dependencies for.
        if (argv.init) {
            // Generate keys, nonces, and hashes for both.

            fs.writeFileSync(filename, JSON.stringify(loaded_messages));
        } else {
            loaded_messages = require(filename);
        }
        // Load key(s)
        // Generate message(s)

    });
