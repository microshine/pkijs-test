interface ISerializable {
    toJSON(): any;
}
interface IBerBlock {
    /**
     * Base function for converting block from BER encoded array of bytes
     * @param  {ArrayBuffer} input_buffer   ASN.1 BER encoded array
     * @param  {number} input_offset        Offset in ASN.1 BER encoded array where decoding should be started
     * @param  {number} input_length        Maximum length of array of bytes which can be using in this function
     * @returns number
     */
    fromBER(input_buffer: ArrayBuffer, input_offset: number, input_length: number): number;
    /**
     * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
     * @param  {boolean} size_only      Flag that we need only a size of encoding, not a real array of bytes
     */
    toBER(size_only: boolean): ArrayBuffer;
}

interface IBaseBlock {
    block_name?: string;
    block_length?: number;
    error?: String;
    warnings?: String[];
    value_before_decode?: ArrayBuffer;
}

/**
 * General class of all ASN.1 blocks
 */
declare class BaseBlock implements IBaseBlock, ISerializable, IBerBlock {
    block_name: string;
    block_length: number;
    error: String;
    warnings: String[];
    value_before_decode: ArrayBuffer;

    constructor(obj: IBaseBlock);
    /**
     * Base function for converting block from BER encoded array of bytes
     * @param  {ArrayBuffer} input_buffer   ASN.1 BER encoded array
     * @param  {number} input_offset        Offset in ASN.1 BER encoded array where decoding should be started
     * @param  {number} input_length        Maximum length of array of bytes which can be using in this function
     * @returns number
     */
    fromBER(input_buffer: ArrayBuffer, input_offset: number, input_length: number): number;
    /**
     * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
     * @param  {boolean} size_only      Flag that we need only a size of encoding, not a real array of bytes
     */
    toBER(size_only: boolean): ArrayBuffer;
    /**
     * Convertion for the block to JSON object
     */
    toJSON(): any;
}

declare class HexBlock extends BaseBlock {
    is_hex_only: boolean;
    value_hex: ArrayBuffer;
    /**
     * Descendant of "base_block" with internal ArrayBuffer.
     * Need to have it in case it is not possible to store ASN.1 value in native formats
     */
    constructor();
    constructor(obj: IAsn1Block);

}

declare class IdentificationBlock extends HexBlock {
    tag_class: number;
    tag_number: number;
    is_constructed: boolean;
    constructor(obj: IAsn1Block);
}

declare class LengthBlock extends BaseBlock {
    is_indefinite_form: boolean;
    long_form_used: boolean;
    length: number;
    block_name: string;
    constructor(obj: IAsn1Block);
}

interface IAsn1Block extends IBaseBlock {
    id_block?: IdentificationBlock;
    len_block?: LengthBlock;
    value_block?: BaseBlock;
    value?: any;
    value_date?: Date;
    name?: string;
    optional?: boolean;
    primitive_schema?: any;
    value_hex?: ArrayBuffer;

}

declare namespace org {

}

declare namespace org.pkijs {

    interface ICryptoEngine {
        name: string;
        crypto: Crypto;
        subtle: SubtleCrypto;
    }

    /**
     * Setting the global "crypto engine" parameters
     * @param  {string} name            Auxiliary name for "crypto engine"
     * @param  {Crypto} crypto          Object handling all root cryptographic requests (in fact currently it must handle only "getRandomValues")
     * @param  {SubtleCrypto} subtle    Object handling all main cryptographic requests
     */
    function setEngine(name: string, crypto: Crypto, subtle: SubtleCrypto): void;
    /**
     * Getting information about the global "crypto engine"
     */
    function getEngine(): ICryptoEngine;
    function getCrypto(): SubtleCrypto;
    function emptyObject(): void;
    /**
     * Get correct "names" array for all "schema" objects
     * @param  {any} arg
     */
    function getNames(arg: any): {};
    function inheriteObjectFields(from: any): void;
    /**
     * Making UTC date from local date
     * @param  {Date} date  Date to convert from
     * @returns Date
     */
    function getUTCDate(date: Date): Date;
    function padNumber(input_number: number, full_length: number): string;
    function getValue(args: any, item: any, default_value: any): any;
    /**
     * Compare two Uint8Arrays
     * @param  {Uint8Array} input_view1     First Uint8Array for comparision
     * @param  {Uint8Array} input_view2     Second Uint8Array for comparision
     * @returns boolean
     */
    function isEqual_view(input_view1: Uint8Array, input_view2: Uint8Array): boolean;
    /**
     * Compare two array buffers
     * @param  {ArrayBuffer} input_buffer1      First ArrayBuffer for comparision
     * @param  {ArrayBuffer} input_buffer2      Second ArrayBuffer for comparision
     * @returns boolean
     */
    function isEqual_buffer(input_buffer1: ArrayBuffer, input_buffer2: ArrayBuffer): boolean;
    /**
     * String preparation function. In a future here will be realization of algorithm from RFC4518.
     * @param  {string} input_string        JavaScript string. As soon as for each ASN.1 string type we have a specific transformation function here we will work with pure JavaScript string
     * @returns string                      Formated string
     */
    function stringPrep(input_string: string): string;
    function bufferToHexCodes(input_buffer: ArrayBuffer, input_offset: number, input_lenght: number): string;
    /**
     * Create an ArrayBuffer from string having hexdecimal codes
     * @param  {string} hexString       String to create ArrayBuffer from
     * @returns ArrayBuffer
     */
    function bufferFromHexCodes(hexString: string): ArrayBuffer;
    /**
     * Generates random value
     * @param  {ArrayBufferView} view        New array which gives a length for random value
     * @returns ArrayBufferView
     */
    function getRandomValues(view: ArrayBufferView): ArrayBufferView;
    interface IAlgorithm extends Algorithm {
        name: string;
        modulusLength?: number;
        publicExponent?: ArrayBufferView;
        hash?: Algorithm;
        saltLength?: number;
        namedCurve?: string;
        publicKey?: CryptoKey;
        length?: number;
        counter?: ArrayBufferView;
        iv?: ArrayBufferView;
        salt?: ArrayBufferView;
        info?: ArrayBufferView;
        iterations?: number;
        kdf?: string;
    }
    interface IAlgorithmParameters {
        algorithm: IAlgorithm;
        usages: string[];
    }
    /**
     * @param  {string} algorithmName       Algorithm name to get common parameters for
     * @param  {string} operation           Kind of operation: "sign", "encrypt", "generatekey", "importkey", "exportkey", "verify"
     * @returns IAlgorithmParameters
     */
    function getAlgorithmParameters(algorithmName: string, operation: string): IAlgorithmParameters;
    /**
     * Get OID for each specific WebCrypto algorithm
     * @param  {Algorithm} algorithm        WebCrypto algorithm
     * @returns string
     */
    function getOIDByAlgorithm(algorithm: IAlgorithm): string;
    /**
     * Get WebCrypto algorithm by wel-known OID
     * @param  {string} oid     Wel-known OID to search for
     */
    function getAlgorithmByOID(oid: string): IAlgorithm;
    /**
     * Getting hash algorithm by signature algorithm
     * @param  {org.pkijs.simpl.ALGORITHM_IDENTIFIER} signatureAlgorithm     Signature algorithm
     */
    function getHashAlgorithm(signatureAlgorithm: any): string;
    /**
     * Create CMS ECDSA signature from WebCrypto ECDSA signature
     * @param  {ArrayBuffer} signatureBuffer    WebCrypto result of "sign" function
     * @returns ArrayBuffer
     */
    function createCMSECDSASignature(signatureBuffer: ArrayBuffer): ArrayBuffer;
    /**
     * Create a single ArrayBuffer from CMS ECDSA signature
     * @param  {org.pkijs.asn1.SEQUENCE} cmsSignature       ASN.1 SEQUENCE contains CMS ECDSA signature
     * @returns ArrayBuffer
     */
    function createECDSASignatureFromCMS(cmsSignature: any): ArrayBuffer;
    /**
     * Get encryption algorithm OID by WebCrypto algorithm"s object
     * @param  {IAlgorithm} algorithm       WebCrypto algorithm object
     * @returns string
     */
    function getEncryptionAlgorithm(algorithm: IAlgorithm): string;
    /**
     * Get encryption algorithm name by OID
     * @param  {string} oid OID of encryption algorithm
     * @returns string
     */
    function getAlgorithmByEncryptionOID(oid: string): string;

    interface IFromBerReuslt {
        result: IAsn1Block;
        offset: number;
    }
    /**
     * Major function for decoding ASN.1 BER array into internal library structuries
     * @param {ArrayBuffer} input_buffer ASN.1 BER encoded array of bytes
     */
    function fromBER(input_buffer: ArrayBuffer): IFromBerReuslt;
}

declare namespace org.pkijs.asn1 {
    class ASN1_block extends BaseBlock implements IAsn1Block {
        id_block: IdentificationBlock;
        len_block: LengthBlock;
        value_block: BaseBlock;
        name: string;
        optional: boolean;
        primitive_schema: any;
        value_hex: ArrayBuffer;
        constructor();
        constructor(obj: IAsn1Block);
        /**
         * Base function for converting block from BER encoded array of bytes
         * @param  {ArrayBuffer} input_buffer   ASN.1 BER encoded array
         * @param  {number} input_offset        Offset in ASN.1 BER encoded array where decoding should be started
         * @param  {number} input_length        Maximum length of array of bytes which can be using in this function
         * @returns number
         */
        fromBER(input_buffer: ArrayBuffer, input_offset: number, input_length: number): number;
        /**
         * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
         * @param  {boolean} size_only      Flag that we need only a size of encoding, not a real array of bytes
         */
        toBER(size_only: boolean): ArrayBuffer;
        /**
         * Convertion for the block to JSON object
         * @returns IAsn1BlockJSON
         */
        toJSON(): any;
    }

    let INTEGER: any;
    let BITSTRING: any;
    let PRINTABLESTRING: any;
}

declare namespace org.pkijs.simpl {
    let ALGORITHM_IDENTIFIER: any;
    let PUBLIC_KEY_INFO: any;
    let ATTR_TYPE_AND_VALUE: any;
    let RDN: any;
    let EXTENSION: any;
    let EXTENSIONS: any;
    let CERT: any;
    let REV_CERT: any;
    let CRL: any;
    let ATTRIBUTE: any;
    let PKCS10: any;
    let PKCS8: any;
    let CERT_CHAIN: any;
}
declare namespace org.pkijs.simpl.x509 {
    let BasicConstraints: any;
}