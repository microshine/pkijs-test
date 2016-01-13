var assert = require("assert");
var fs = require("fs");
var SSL = require("node-webcrypto-ossl").default;

var TEST_DIR = "test";
var RESOURCE_DIR = TEST_DIR + "/resources";

var TEST_CONTENT = "Test content for Mocha tests";

// var common = require("asn1js/org/pkijs/common");
var merge = require("node.extend");
var co = require("co");

var common = require("pkijs/org/pkijs/common");
var asn1js = require("asn1js");
var x509_schema = require("pkijs/org/pkijs/x509_schema");
var x509_simpl = require("pkijs/org/pkijs/x509_simpl");
var cms_schema = require("pkijs/org/pkijs/cms_schema");
var cms_simple = require("pkijs/org/pkijs/cms_simpl");
var ocsp_tsp_schema = require("pkijs/org/pkijs/ocsp_tsp_schema");
var ocsp_tsp_simpl = require("pkijs/org/pkijs/ocsp_tsp_simpl");

var org = merge(true, asn1js, common);
org = merge(true, org, x509_schema);
org = merge(true, org, x509_simpl);
org = merge(true, org, cms_schema);
org = merge(true, org, cms_simple);
org = merge(true, org, ocsp_tsp_schema);
org = merge(true, org, ocsp_tsp_simpl);
org = merge(true, org, co);

org = org.org;

common.org = org;
asn1js.org = org;
x509_schema.org = org;
x509_simpl.org = org;
cms_schema.org = org;
cms_simple.org = org;
ocsp_tsp_schema.org = org;
ocsp_tsp_simpl.org = org;

//console.log(org);

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

describe("CMS Encrypt", function () {
    it("Encrypt", function (done) {
        var ssl = new SSL();
        org.pkijs.setEngine("ossl", ssl, ssl.subtle);

        var sequence = Promise.resolve();

        var cert_simpl = new org.pkijs.simpl.CERT();

        var publicKey;
        var privateKey;
        var cmsEnveloped;

        var hash_algorithm = "sha-1";
        var signature_algorithm_name = "RSASSA-PKCS1-V1_5";

        var encodedCertificate;
        
        // #region Get a "crypto" extension 
        var crypto = org.pkijs.getCrypto();
        if (typeof crypto == "undefined") {
            console.log("No WebCrypto extension found");
            return;
        }
        // #endregion 

        // #region Put a static values 
        cert_simpl.version = 2;
        cert_simpl.serialNumber = new org.pkijs.asn1.INTEGER({ value: 1 });
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6", // Country name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.issuer.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3", // Common name
            value: new org.pkijs.asn1.BMPSTRING({ value: "Test" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.6", // Country name
            value: new org.pkijs.asn1.PRINTABLESTRING({ value: "RU" })
        }));
        cert_simpl.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
            type: "2.5.4.3", // Common name
            value: new org.pkijs.asn1.BMPSTRING({ value: "Test" })
        }));

        cert_simpl.notBefore.value = new Date(2013, 1, 1);
        cert_simpl.notAfter.value = new Date(2016, 1, 1);

        cert_simpl.extensions = new Array(); // Extensions are not a part of certificate by default, it's an optional array

        // #region "KeyUsage" extension 
        var bit_array = new ArrayBuffer(1);
        var bit_view = new Uint8Array(bit_array);

        bit_view[0] = bit_view[0] | 0x02; // Key usage "cRLSign" flag
        //bit_view[0] = bit_view[0] | 0x04; // Key usage "keyCertSign" flag

        var key_usage = new org.pkijs.asn1.BITSTRING({ value_hex: bit_array });

        cert_simpl.extensions.push(new org.pkijs.simpl.EXTENSION({
            extnID: "2.5.29.15",
            critical: false,
            extnValue: key_usage.toBER(false),
            parsedValue: key_usage // Parsed value for well-known extensions
        }));
        // #endregion 
        // #endregion 

        // #region Create a new key pair 
        sequence = sequence.then(
            function () {
                // #region Get default algorithm parameters for key generation 
                var algorithm = org.pkijs.getAlgorithmParameters(signature_algorithm_name, "generatekey");
                if ("hash" in algorithm.algorithm)
                    algorithm.algorithm.hash.name = hash_algorithm;
                // #endregion 

                return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
            }
            );
        // #endregion 

        // #region Store new key in an interim variables
        sequence = sequence.then(
            function (keyPair) {
                publicKey = keyPair.publicKey;
                privateKey = keyPair.privateKey;
            },
            function (error) {
                console.log("Error during key generation: " + error);
            }
            );
        // #endregion 

        // #region Exporting public key into "subjectPublicKeyInfo" value of certificate 
        sequence = sequence.then(
            function () {
                return cert_simpl.subjectPublicKeyInfo.importKey(publicKey);
            }
            );
        // #endregion 

        // #region Signing final certificate 
        sequence = sequence.then(
            function () {
                return cert_simpl.sign(privateKey, hash_algorithm);
            },
            function (error) {
                console.log("Error during exporting public key: " + error);
            }
            );
        // #endregion 

        // #region Encode and store certificate 
        sequence = sequence.then(
            function () {
                certificateBuffer = cert_simpl.toSchema(true).toBER(false);

                var cert_simpl_string = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

                var result_string = "-----BEGIN CERTIFICATE-----\r\n";
                result_string = result_string + formatPEM(new Buffer(cert_simpl_string, "binary").toString("base64"));
                result_string = result_string + "\r\n-----END CERTIFICATE-----\r\n";

                encodedCertificate = result_string;

                console.log("Certificate created successfully!");
            },
            function (error) {
                console.log("Error during signing: " + error);
            }
            );
        // #endregion 

        // #region Exporting private key 
        sequence = sequence.then(
            function () {
                return crypto.exportKey("pkcs8", privateKey);
            }
            );
        // #endregion 

        // #region Store exported key on Web page
        var private_key_string;
        sequence = sequence.then(
            function (result) {
                private_key_string = String.fromCharCode.apply(null, new Uint8Array(result));

                var result_string = "";

                result_string = result_string + "-----BEGIN PRIVATE KEY-----\r\n";
                result_string = result_string + formatPEM(new Buffer(private_key_string, "binary").toString("base64"));
                result_string = result_string + "\r\n-----END PRIVATE KEY-----\r\n";

                console.log(result_string);
                console.log("Private key exported successfully!");
                
                //Encrypt

                // #region Create WebCrypto form of content encryption algorithm 
                var encryptionAlgorithm = {
                    name: "AES-CBC",
                    length: 256
                };

                // #endregion 

                cmsEnveloped = new org.pkijs.simpl.CMS_ENVELOPED_DATA();

                cmsEnveloped.addRecipientByCertificate(cert_simpl);
                return cmsEnveloped.encrypt(encryptionAlgorithm, stringToArrayBuffer(TEST_CONTENT));
            });


        sequence = sequence.then(function (result) {
            var cms_content_simpl = new org.pkijs.simpl.CMS_CONTENT_INFO();
            cms_content_simpl.contentType = "1.2.840.113549.1.7.3";
            cms_content_simpl.content = cmsEnveloped.toSchema();

            var schema = cms_content_simpl.toSchema();
            var ber = schema.toBER(false);

            var ber_string = String.fromCharCode.apply(null, new Uint8Array(ber));

            var result_string = "-----BEGIN CMS-----\r\n";
            result_string = result_string + formatPEM(new Buffer(ber_string, "binary").toString("base64"));
            result_string = result_string + "\r\n-----END CMS-----\r\n";

            console.log(result_string);

            console.log("Encryption process finished successfully"); 

            // #region Decode CMS Enveloped content 
            var cms_enveloped_simp = new org.pkijs.simpl.CMS_ENVELOPED_DATA({ schema: cms_content_simpl.content });
            // #endregion 

            return cms_enveloped_simp.decrypt(0,
                {
                    recipientCertificate: cert_simpl,
                    recipientPrivateKey: stringToArrayBuffer(private_key_string)
                })
        })

        sequence = sequence.then(function (result) {
            console.log(arrayBufferToString(result));
        })

        sequence = sequence.then(done, done);
    })
});