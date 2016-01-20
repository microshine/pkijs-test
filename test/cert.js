var assert = require("assert");
var fs = require("fs");

var CRYPTO_OSSL = false;

var SSL;
if (CRYPTO_OSSL) {
    // Node.js
    SSL = new require("node-webcrypto-ossl").default;
}
else {
    // PKCS11
    PKCS11 = require("node-webcrypto-p11");
    SSL = new PKCS11({
        library: "/usr/local/lib/softhsm/libsofthsm2.so",
        name: "Luna 5",
        slot: 0,
        pin: "12345"
    });
}
var TEST_DIR = "test";
var RESOURCE_DIR = TEST_DIR + "/resources";

// var common = require("asn1js/org/pkijs/common");
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


function loadCertificate(fileName) {
    var cert_str = fs.readFileSync(RESOURCE_DIR + "/" + fileName, "utf8");
    var cert = read_pem_cert(cert_str);
    assert.equal(cert != null, true, "Can not parse certificate");
    return cert;
}

function formatPEM(pem_string) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pem_string" type="String">String to format</param>
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
//*********************************************************************************
function arrayBufferToString(buffer) {
    /// <summary>Create a string from ArrayBuffer</summary>
    /// <param name="buffer" type="ArrayBuffer">ArrayBuffer to create a string from</param>
    var result_string = "";
    var view = new Uint8Array(buffer);
    for (var i = 0; i < view.length; i++)
        result_string = result_string + String.fromCharCode(view[i]);
    return result_string;
}
//*********************************************************************************
function stringToArrayBuffer(str) {
    /// <summary>Create an ArrayBuffer from string</summary>
    /// <param name="str" type="String">String to create ArrayBuffer from</param>
    var stringLength = str.length;
    var resultBuffer = new ArrayBuffer(stringLength);
    var resultView = new Uint8Array(resultBuffer);
    for (var i = 0; i < stringLength; i++)
        resultView[i] = str.charCodeAt(i);
    return resultBuffer;
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

/**
 * Converts PEM to BER
 */
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
};

describe("Certificate", function () {

    before(function (done) {
        done();
    })

    it("Create", function (done) {        
        // Initial variables
        var ssl = SSL;
        org.pkijs.setEngine("ossl", ssl, ssl.subtle);
        var sequence = Promise.resolve();
        var cert_simpl = new org.pkijs.simpl.CERT();
        var publicKey;
        var privateKey;
        
        // region Get a "crypto" extension 
        var crypto = org.pkijs.getCrypto();
        if (typeof crypto == "undefined") {
            throw new Error("No WebCrypto extension found");
            return;
        } 
        // Put a static values
        cert_simpl.version = 2;
        cert_simpl.serialNumber = new org.pkijs.asn1.INTEGER({ value: 1 });
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6", // Country name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3", // Common name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "Test" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6", // Country name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3", // Common name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "Test" })
        }));
        cert_simpl.notBefore.value = new Date(2013, 1, 1);
        cert_simpl.notAfter.value = new Date(2016, 1, 1);
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
        sequence = sequence.then(
            function () {
                // Get default algorithm parameters for key generation 
                var algorithm = org.pkijs.getAlgorithmParameters("RSASSA-PKCS1-v1_5", "generatekey");
                if ("hash" in algorithm.algorithm)
                    algorithm.algorithm.hash.name = "SHA-1";

                return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
            })
            .then(function (keyPair) {
                // Store new key in an interim variables
                publicKey = keyPair.publicKey;
                privateKey = keyPair.privateKey;
            })
            .then(function () {
                // Store new key in an interim variables
                return crypto.exportKey("spki", publicKey)
            })
            .then(function (b) {
                // Exporting public key into "subjectPublicKeyInfo" value of certificate 
                console.log("Exporting public key into 'subjectPublicKeyInfo' value of certificate");
                return cert_simpl.subjectPublicKeyInfo.importKey(publicKey);
            })
            .then(function () {
                // Signing final certificate
                return cert_simpl.sign(privateKey, "SHA-1");
            })
            .then(function () {
                // Encode and store certificate
                var cert_simpl_encoded = cert_simpl.toSchema(true).toBER(false);
                var cert_simpl_string = String.fromCharCode.apply(null, new Uint8Array(cert_simpl_encoded));
                var result_string = "-----BEGIN CERTIFICATE-----\r\n";
                result_string = result_string + formatPEM(new Buffer(cert_simpl_string, "binary").toString("base64"));
                result_string = result_string + "\r\n-----END CERTIFICATE-----\r\n";
                console.log(result_string);
            })
            .then(function () {
                // Exporting private key 
                return crypto.exportKey("pkcs8", privateKey);
            })
            .then(function (result) {
                var private_key_string = String.fromCharCode.apply(null, new Uint8Array(result));
                var result_string = "";
                result_string = result_string + "-----BEGIN PRIVATE KEY-----\r\n";
                result_string = result_string + formatPEM(new Buffer(private_key_string, "binary").toString("base64"));
                result_string = result_string + "\r\n-----END PRIVATE KEY-----";
                console.log(result_string);
            })
            .then(function () {
                done();
            })
            .catch(function (e) {
                console.error(e.message);
                console.error(e.stack);
                done();
            })
    })

    it("read PEM", function () {
        var cert_str = fs.readFileSync(RESOURCE_DIR + "/cert-selfsigned.cer", "utf8");
        var cert_simpl = read_pem_cert(cert_str);
        assert.equal(cert_simpl != null, true, "Can not parse certificate");
    })

    it("verify selfsigned", function (done) {
        //get certificate from file
        var cert_str = fs.readFileSync(RESOURCE_DIR + "/cert-selfsigned.cer", "utf8");
        var cert_simpl = read_pem_cert(cert_str);
        assert.equal(cert_simpl != null, true, "Can not parse certificate");

        cert_simpl.verify()
            .then(function (r) {
                assert.equal(r, true, "Error on selfsigned cert verify");
            })
            .then(done, done);
    })

    it("verify certificate", function (done) {
        //get certificate from file
        var ca_str = fs.readFileSync(RESOURCE_DIR + "/cert-ca.cer", "utf8");
        var ca = read_pem_cert(ca_str);
        assert.equal(ca != null, true, "Can not parse certificate");

        var root_str = fs.readFileSync(RESOURCE_DIR + "/cert-root.cer", "utf8");
        var root = read_pem_cert(root_str);
        assert.equal(root != null, true, "Can not parse certificate");

        ca.verify({
            issuerCertificate: root
        })
            .then(function (r) {
                assert.equal(r, true, "Error on CA verify by Root certificate");
            })
            .then(done, done);
    })

    it("verify chain", function (done) {
        var cert = loadCertificate("cert-user.cer");
        var cert2 = loadCertificate("cert-user2.cer");
        var ca = loadCertificate("cert-ca.cer");
        var ca2 = loadCertificate("cert-ca2.cer");
        var root = loadCertificate("cert-root.cer");
        var root2 = loadCertificate("cert-root2.cer");

        var chain = new org.pkijs.simpl.CERT_CHAIN({
            checkDate: new Date(),
            trusted_certs: [root2],
            certs: [ca2, cert2, ca]
        })
        chain.verify()
            .then(function (r) {
                assert.equal(r.result, true, "Error on Chain verify");
            })
            .then(done, done);
    })

})
