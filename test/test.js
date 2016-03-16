var fs = require("fs");
var DIR_TEST = "test";
var DIR_RESOURCE = "resources";
var merge = require("node.extend");
var co = require("co");
var common = require("pkijs/org/pkijs/common");
var _asn1js = require("asn1js");
var _pkijs = require("pkijs");
var _x509schema = require("pkijs/org/pkijs/x509_schema");
var asn1js = merge(true, _asn1js, common);
var x509schema = merge(true, _x509schema, asn1js);
var pkijs_1 = merge(true, _pkijs, asn1js);
var pkijs_2 = merge(true, pkijs_1, co);
var org = merge(true, pkijs_1, x509schema).org;
/**
 * Format string in order to have each line with length equal to 63
 * @param {string} pem_string String to format
 */
function formatPEM(pem_string) {
    var string_length = pem_string.length;
    var result_string = "";
    for (var i = 0, count = 0; i < string_length; i++ , count++) {
        if (count > 63) {
            result_string = result_string + "\r\n";
            count = 0;
        }
        result_string = result_string + pem_string[i];
    }
    return result_string;
}
function read_pem_cert(buf) {
    var cert_str = buf.toString().replace(/[\r\n]/g, "");
    var certificateBuffer = pem2ber(cert_str);
    var asn1 = org.pkijs.fromBER(certificateBuffer);
    var cert_simpl = new org.pkijs.simpl.CERT({ schema: asn1.result });
    return cert_simpl;
}
/**
 * Converts Buffer to ArrayBuffer
 */
function b2ab(b) {
    return new Uint8Array(b).buffer;
}
function pem2ber(text) {
    var re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
    var m = re.exec(text);
    if (m) {
        if (m[1])
            text = m[1];
        else if (m[2])
            text = m[2];
        else
            throw "RegExp out of sync";
    }
    var b = new Buffer(text, "base64");
    return b2ab(b);
}
;
/// <reference path="utils.ts" />
var CRYPTO_OSSL = true;
var SSL;
if (CRYPTO_OSSL) {
    // Node.js
    var ossl = require("node-webcrypto-ossl").default;
    SSL = new ossl();
}
else {
    // PKCS11
    var pkcs11 = require("node-webcrypto-p11");
    SSL = new pkcs11({
        library: "/usr/local/lib/softhsm/libsofthsm2.so",
        name: "Luna 5",
        slot: 0,
        pin: "12345"
    });
}

var assert = require("assert");

var ssl = SSL;
org.pkijs.setEngine("ossl", ssl, ssl.subtle);

var cert_str = fs.readFileSync(DIR_RESOURCE + "/cert-root.cer", "utf8");
var cert = read_pem_cert(cert_str);
cert.verify()
    .then(function(verify) {
        assert.equal(verify, true, "Certificate is not valid");
    })
    .then(function() { console.log("success") }, function(e) { console.log(e.message); console.log(e.stack) });