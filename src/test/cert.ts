/// <reference path="../provider.ts" />

let assert = require("assert");

describe("Certificate", () => {

    before(() => {
        let ssl: Crypto = SSL;
        org.pkijs.setEngine("provider", ssl, ssl.subtle);
    });

    it("create self-signed", (done) => {
        // Initial variables
        let sequence = Promise.resolve();
        let cert_simpl = new org.pkijs.simpl.CERT();
        let publicKey: CryptoKey;
        let privateKey: CryptoKey;

        // region Get a "crypto" extension 
        let crypto = org.pkijs.getCrypto();
        assert.equal(!!crypto, true);

        // fill Certificate schema
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
        cert_simpl.notBefore.value = new Date(2016, 1, 1);
        cert_simpl.notAfter.value = new Date(2020, 1, 1);
        cert_simpl.extensions = new Array(); // Extensions are not a part of certificate by default, it's an optional array

        // "BasicConstraints" extension
        let basic_constr = new org.pkijs.simpl.x509.BasicConstraints({
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
        let bit_array = new ArrayBuffer(1);
        let bit_view = new Uint8Array(bit_array);
        bit_view[0] = bit_view[0] | 0x02; // Key usage "cRLSign" flag
        bit_view[0] = bit_view[0] | 0x04; // Key usage "keyCertSign" flag
        let key_usage = new org.pkijs.asn1.BITSTRING({ value_hex: bit_array });
        cert_simpl.extensions.push(new org.pkijs.simpl.EXTENSION({
            extnID: "2.5.29.15",
            critical: false,
            extnValue: key_usage.toBER(false),
            parsedValue: key_usage // Parsed value for well-known extensions
        }));

        // Create a new key pair 
        sequence = sequence.then(() => {
            // Get default algorithm parameters for key generation 
            let algorithm = org.pkijs.getAlgorithmParameters("RSASSA-PKCS1-v1_5", "generatekey");
            if ("hash" in algorithm.algorithm)
                algorithm.algorithm.hash.name = "SHA-1";

            return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
        })
            .then((keyPair: CryptoKeyPair) => {
                // Store new key in an interim variables
                assert.equal(!!keyPair, true);
                assert.equal(!!keyPair.publicKey, true);
                assert.equal(!!keyPair.privateKey, true);
                publicKey = keyPair.publicKey;
                privateKey = keyPair.privateKey;
                return crypto.exportKey("spki", publicKey);
            })
            .then((b: ArrayBuffer) => {
                assert.equal(!!(new Uint8Array(b).length), true);
                // Exporting public key into "subjectPublicKeyInfo" value of certificate 
                return cert_simpl.subjectPublicKeyInfo.importKey(publicKey);
            })
            .then((spki: ArrayBuffer) => {
                // Signing final certificate
                return cert_simpl.sign(privateKey, "SHA-1");
            })
            .then(() => {
                // Encode and store certificate
                let cert_simpl_encoded = cert_simpl.toSchema(true).toBER(false);
                assert.equal(!!(new Uint8Array(cert_simpl_encoded).length), true);
            })
            .then(() => {
                // Exporting private key 
                return crypto.exportKey("pkcs8", privateKey);
            })
            .then((result: ArrayBuffer) => {
                assert.equal(!!(new Uint8Array(result).length), true);
                let private_key_string = String.fromCharCode.apply(null, new Uint8Array(result));
            })
            .then(done, done);
    });

    it("read certificate from file and verify RSA", function(done) {
        let cert_str = fs.readFileSync(DIR_RESOURCE + "/cert-root.cer", "utf8");
        let cert = read_pem_cert(cert_str);
        cert.verify()
            .then((verify: boolean) => {
                assert.equal(verify, true, `Certificate is not valid`);
            })
            .then(done, done);
    });

    it("read certificate from file and verify EC", function(done) {
        let cert_str = fs.readFileSync(DIR_RESOURCE + "/cert-ec-self.cer", "utf8");
        let cert = read_pem_cert(cert_str);
        cert.verify()
            .then((verify: boolean) => {
                assert.equal(verify, true, `Certificate is not valid`);
            })
            .then(done, done);
    });

});