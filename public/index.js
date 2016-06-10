// Example for CSR from here: https://pkijs.org/examples/PKCS10_complex_example.html

//---- Helpers
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

/* converts ArrayBuffer to string */
function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

/* helper to add subject attributes to a PKCS10 CSR */
org.pkijs.simpl.PKCS10.prototype.addSubjectAttr = function (type, value) {
    let typemap = {
        "C":    { key: "2.5.4.6", type: org.pkijs.asn1.PRINTABLESTRING},
        "OU":   { key: "2.5.4.11", type: org.pkijs.asn1.UTF8STRING},
        "O":    { key: "2.5.4.10", type: org.pkijs.asn1.UTF8STRING},
        "CN":   { key: "2.5.4.3", type: org.pkijs.asn1.UTF8STRING},
        "L":    { key: "2.5.4.7", type: org.pkijs.asn1.UTF8STRING},
        "S":    { key: "2.5.4.8", type: org.pkijs.asn1.UTF8STRING},
        "T":    { key: "2.5.4.12", type: org.pkijs.asn1.UTF8STRING},
        "GN":   { key: "2.5.4.42", type: org.pkijs.asn1.UTF8STRING},
        "I":    { key: "2.5.4.43", type: org.pkijs.asn1.UTF8STRING},
        "SN":   { key: "2.5.4.4", type: org.pkijs.asn1.UTF8STRING},
        "E-mail": { key: "1.2.840.113549.1.9.1", type: org.pkijs.asn1.UTF8STRING},
    };
    if (!(type in typemap)) {
        console.log("Cannot push " + type + "/" + value);
    }
    this.subject.types_and_values.push(new org.pkijs.simpl.ATTR_TYPE_AND_VALUE({
        type: typemap[type].key,
        value: new typemap[type].type({value: value})
    }));
};

/* encodes a binary privkey in PEM */
function privkey2pem(privkey) {
    var privkeyStr = String.fromCharCode.apply(null, new Uint8Array(privkey));

    let pem = "\r\n-----BEGIN PRIVATE KEY-----\r\n";
    pem += formatPEM(window.btoa(privkeyStr));
    pem += "\r\n-----END PRIVATE KEY-----";
    return pem;
}

/* encodes a CSR into PEM */
function csr2pem(csr) {
    let schema = csr.toSchema();
    let ber = schema.toBER(false);

    let csrPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
    csrPem += formatPEM(window.btoa(ab2str(ber)));
    csrPem += "\r\n-----END CERTIFICATE REQUEST-----\r\n";

    return csrPem;
}

/* copy the value of the dom element into the CSR */
function populateAttr(cert,attr){
    cert.addSubjectAttr(attr, document.getElementById(attr).value);
}

/* generates a keypair and prepares a PKCS10 CSR */
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

    populateAttr(pkcs10CSR,'C');
    populateAttr(pkcs10CSR,'CN');
    populateAttr(pkcs10CSR,'L');
    populateAttr(pkcs10CSR,'O');
    populateAttr(pkcs10CSR,'OU');

    //---- create key pair
    return Promise.resolve().then(function () {
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
        return pems;
    })
}

/* creates a PKCS10 CSR and signs it */
function getClientCert(){
    createPKCS10()
        .then(([csr, priv])=>{
            return Promise.all([post('cert.pem',csr),priv]);
        })
        .then(pems=>{
            return pems.join('');
        })
        .then(cert=>{
            console.log(cert);
            download('client.crt',cert);
        })
}

/* promisify XHR req */
function post(url,str) {
  return new Promise(function(resolve, reject) {
    var req = new XMLHttpRequest();
    req.open('POST', url);
    req.setRequestHeader("Content-Type", "text/plain");

    req.onload = function() {
      if (req.status >= 200 && req.status < 300) {
        resolve(req.response);
      }else {
        reject(Error(req.statusText));
      }
    };

    req.onerror = function() {
      reject(Error("Network Error"));
    };
    req.send(str);
  });
}

/* helper to 'download' a local file */
function download(filename, text) {
    var pom = document.createElement('a');
    pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    pom.setAttribute('download', filename);

    if (document.createEvent) {
        var event = document.createEvent('MouseEvents');
        event.initEvent('click', true, true);
        pom.dispatchEvent(event);
    }
    else {
        pom.click();
    }
}


