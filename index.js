// Example for CSR from here: https://pkijs.org/examples/PKCS10_complex_example.html
function formatPEM(pemStr) {

    var strlen = pemStr.length;
    var pem = "";

    for (var i = 0, count = 0; i < strlen; i++, count++) {
        if (count > 63) {
            pem += "\r\n";
            count = 0;
        }
        pem += pemStr[i];
    }
    return pem;
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

org.pkijs.simpl.PKCS10.prototype.addSubjectAttr = function (type, value) {
    let typemap = {
        "C": "2.5.4.6",
        "OU": "2.5.4.11",
        "O": "2.5.4.10",
        "CN": "2.5.4.3",
        "L": "2.5.4.7",
        "S": "2.5.4.8",
        "T": "2.5.4.12",
        "GN": "2.5.4.42",
        "I": "2.5.4.43",
        "SN": "2.5.4.4",
        "E-mail": "1.2.840.113549.1.9.1"
    };
    if (!(type in typemap)) {
        console.log("Cannot push " + type + "/" + value);
    }
    this.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
        type: typemap[type],
        value: new org.pkijs.asn1.UTF8STRING({value: value})
    }));
};

function privkey2pem(privkey) {
    var privkeyStr = String.fromCharCode.apply(null, new Uint8Array(privkey));

    let pem = "\r\n-----BEGIN PRIVATE KEY-----\r\n";
    pem += formatPEM(window.btoa(privkeyStr));
    pem += "\r\n-----END PRIVATE KEY-----";
    return pem;
}

function csr2pem(csr) {
    let schema = csr.toSchema();
    let ber = schema.toBER(false);

    let csrPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
    csrPem += formatPEM(window.btoa(ab2str(ber)));
    csrPem += "\r\n-----END CERTIFICATE REQUEST-----\r\n";

    return csrPem;
}


function createPKCS10() {
    // #region Initial variables 
    let pkcs10CSR = new org.pkijs.simpl.PKCS10();

    let publicKey;
    let privateKey;

    let hash_algorithm = "sha-512"; //HARDCODE
    let signature_algorithm_name = "ECDSA"; // HARDCODED

    var crypto = org.pkijs.getCrypto();
    if (typeof crypto == "undefined") {
        alert("No WebCrypto extension found");
        return;
    }

    pkcs10CSR.version = 0;
    pkcs10CSR.attributes = [];

    pkcs10CSR.addSubjectAttr("C", "CH");
    pkcs10CSR.addSubjectAttr("CN", "Thomas");

    //---- create key pair
    Promise.resolve().then(function () {
        let algorithm = org.pkijs.getAlgorithmParameters(signature_algorithm_name, "generatekey");
        if ("hash" in algorithm.algorithm) {
            algorithm.algorithm.hash.name = hash_algorithm;
        }

        return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    }).then(function (keyPair) {
        publicKey = keyPair.publicKey;
        privateKey = keyPair.privateKey;
    }, function (error) {
        alert("Error during key generation: " + error);
    }).then(function () {
        return pkcs10CSR.subjectPublicKeyInfo.importKey(publicKey);
    }).then(function (result) {
        return crypto.digest({name: "SHA-1"}, pkcs10CSR.subjectPublicKeyInfo.subjectPublicKey.value_block.value_hex);
    }).then(function (result) {
        pkcs10CSR.attributes.push(new org.pkijs.simpl.ATTRIBUTE({
            type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
            values: [(new org.pkijs.simpl.EXTENSIONS({
                extensions_array: [
                    new org.pkijs.simpl.EXTENSION({
                        extnID: "2.5.29.14",
                        critical: false,
                        extnValue: (new org.pkijs.asn1.OCTETSTRING({value_hex: result})).toBER(false)
                    })
                ]
            })).toSchema()]
        }));
    }).then(function () {// Signing final PKCS#10 request
        return pkcs10CSR.sign(privateKey, hash_algorithm);
    }, function (error) {
        alert("Error during exporting public key: " + error);
    }).then(function(){
        return crypto.exportKey("pkcs8", privateKey);
    }).then(function (pkcs8Privkey) {
        return [csr2pem(pkcs10CSR),privkey2pem(pkcs8Privkey)];
    }, function (error) {
        alert("Error signing PKCS#10: " + error);
    }).then(function (pems) {
        let [csr,priv] = pems;
        console.log("Generated: \n" + csr);
        console.log("Generated: \n" + priv);
    })
}
