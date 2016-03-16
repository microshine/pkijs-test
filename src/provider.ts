/// <reference path="utils.ts" />

let CRYPTO_OSSL = true;

let SSL: Crypto;
if (CRYPTO_OSSL) {
    // Node.js
    let ossl: any = require("node-webcrypto-ossl").default;
    SSL = new ossl();
}
else {
    // PKCS11
    let pkcs11 = require("node-webcrypto-p11");
    SSL = new pkcs11({
        library: "/usr/local/lib/softhsm/libsofthsm2.so",
        name: "Luna 5",
        slot: 0,
        pin: "12345"
    });
}