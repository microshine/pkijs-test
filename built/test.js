/// <reference path="pkijs.d.ts" />
/// <reference path="promise.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />
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
    for (var i = 0, count = 0; i < string_length; i++, count++) {
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
/// <reference path="../provider.ts" />
var assert = require("assert");
describe("Certificate", function () {
    before(function () {
        var ssl = SSL;
        org.pkijs.setEngine("provider", ssl, ssl.subtle);
    });
    it("create self-signed", function (done) {
        // Initial variables
        var sequence = Promise.resolve();
        var cert_simpl = new org.pkijs.simpl.CERT();
        var publicKey;
        var privateKey;
        // region Get a "crypto" extension 
        var crypto = org.pkijs.getCrypto();
        assert.equal(!!crypto, true);
        // fill Certificate schema
        // Put a static values
        cert_simpl.version = 2;
        cert_simpl.serialNumber = new org.pkijs.asn1.INTEGER({ value: 1 });
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6",
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3",
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "Test" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6",
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3",
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "Test" })
        }));
        cert_simpl.notBefore.value = new Date(2016, 1, 1);
        cert_simpl.notAfter.value = new Date(2020, 1, 1);
        cert_simpl.extensions = new Array(); // Extensions are not a part of certificate by default, it's an optional array
        // "BasicConstraints" extension
        var basic_constr = new org.pkijs.simpl.x509.BasicConstraints({
            cA: true,
            pathLenConstraint: 3
        });
        cert_simpl.extensions.push(new org.pkijs.simpl.EXTENSION({
            extnID: "2.5.29.19",
            critical: false,
            extnValue: basic_constr.toSchema().toBER(false),
            parsedValue: basic_constr // Parsed value for well-known extensions
        }));
        // "KeyUsage" extension 
        var bit_array = new ArrayBuffer(1);
        var bit_view = new Uint8Array(bit_array);
        bit_view[0] = bit_view[0] | 0x02; // Key usage "cRLSign" flag
        bit_view[0] = bit_view[0] | 0x04; // Key usage "keyCertSign" flag
        var key_usage = new org.pkijs.asn1.BITSTRING({ value_hex: bit_array });
        cert_simpl.extensions.push(new org.pkijs.simpl.EXTENSION({
            extnID: "2.5.29.15",
            critical: false,
            extnValue: key_usage.toBER(false),
            parsedValue: key_usage // Parsed value for well-known extensions
        }));
        // Create a new key pair 
        sequence = sequence.then(function () {
            // Get default algorithm parameters for key generation 
            var algorithm = org.pkijs.getAlgorithmParameters("RSASSA-PKCS1-v1_5", "generatekey");
            if ("hash" in algorithm.algorithm)
                algorithm.algorithm.hash.name = "SHA-1";
            return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
        })
            .then(function (keyPair) {
            // Store new key in an interim variables
            assert.equal(!!keyPair, true);
            assert.equal(!!keyPair.publicKey, true);
            assert.equal(!!keyPair.privateKey, true);
            publicKey = keyPair.publicKey;
            privateKey = keyPair.privateKey;
            return crypto.exportKey("spki", publicKey);
        })
            .then(function (b) {
            assert.equal(!!(new Uint8Array(b).length), true);
            // Exporting public key into "subjectPublicKeyInfo" value of certificate 
            return cert_simpl.subjectPublicKeyInfo.importKey(publicKey);
        })
            .then(function (spki) {
            // Signing final certificate
            return cert_simpl.sign(privateKey, "SHA-1");
        })
            .then(function () {
            // Encode and store certificate
            var cert_simpl_encoded = cert_simpl.toSchema(true).toBER(false);
            assert.equal(!!(new Uint8Array(cert_simpl_encoded).length), true);
        })
            .then(function () {
            // Exporting private key 
            return crypto.exportKey("pkcs8", privateKey);
        })
            .then(function (result) {
            assert.equal(!!(new Uint8Array(result).length), true);
            var private_key_string = String.fromCharCode.apply(null, new Uint8Array(result));
        })
            .then(done, done);
    });
    it("read certificate from file and verify RSA", function (done) {
        var cert_str = fs.readFileSync(DIR_RESOURCE + "/cert-root.cer", "utf8");
        var cert = read_pem_cert(cert_str);
        cert.verify()
            .then(function (verify) {
            assert.equal(verify, true, "Certificate is not valid");
        })
            .then(done, done);
    });
    it("read certificate from file and verify EC", function (done) {
        var cert_str = fs.readFileSync(DIR_RESOURCE + "/cert-ec-self.cer", "utf8");
        var cert = read_pem_cert(cert_str);
        cert.verify()
            .then(function (verify) {
            assert.equal(verify, true, "Certificate is not valid");
        })
            .then(done, done);
    });
});
