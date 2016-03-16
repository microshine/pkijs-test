/// <reference path="pkijs.d.ts" />
/// <reference path="promise.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

let fs = require("fs");

const DIR_TEST = `test`;
const DIR_RESOURCE = `resources`;

let merge = require("node.extend");
let co = require("co");

let common = require("pkijs/org/pkijs/common");
let _asn1js = require("asn1js");
let _pkijs = require("pkijs");
let _x509schema = require("pkijs/org/pkijs/x509_schema");
let asn1js = merge(true, _asn1js, common);
let x509schema = merge(true, _x509schema, asn1js);
let pkijs_1 = merge(true, _pkijs, asn1js);
let pkijs_2 = merge(true, pkijs_1, co);
let org = merge(true, pkijs_1, x509schema).org;

/**
 * Format string in order to have each line with length equal to 63
 * @param {string} pem_string String to format
 */
function formatPEM(pem_string: string): string {
    let string_length = pem_string.length;
    let result_string = "";
    for (let i = 0, count = 0; i < string_length; i++ , count++) {
        if (count > 63) {
            result_string = result_string + "\r\n";
            count = 0;
        }
        result_string = result_string + pem_string[i];
    }
    return result_string;
}

function read_pem_cert(buf: Buffer) {
    let cert_str = buf.toString().replace(/[\r\n]/g, "");
    let certificateBuffer = pem2ber(cert_str);

    let asn1 = org.pkijs.fromBER(certificateBuffer);
    let cert_simpl = new org.pkijs.simpl.CERT({ schema: asn1.result });
    return cert_simpl;
}

/**
 * Converts Buffer to ArrayBuffer
 */
function b2ab(b: Buffer): ArrayBuffer {
    return new Uint8Array(b).buffer;
}

function pem2ber(text: string): ArrayBuffer {
    let re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
    let m = re.exec(text);
    if (m) {
        if (m[1])
            text = m[1];
        else if (m[2])
            text = m[2];
        else
            throw "RegExp out of sync";
    }
    let b = new Buffer(text, "base64");
    return b2ab(b);
};