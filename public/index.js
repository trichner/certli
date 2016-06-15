// Example for CSR from here: https://pkijs.org/examples/PKCS10_complex_example.html

/* copy the value of the dom element into the CSR */
function populateAttr(cert, attr) {
    cert.addSubjectAttr(attr, document.getElementById(attr).value);
}

/* generates a keypair and prepares a PKCS10 CSR */
function createPKCS10() {
    let pkcs10CSR = new org.pkijs.simpl.PKCS10();

    let publicKey;
    let privateKey;

    let hash_algorithm = "sha-512";
    let signature_algorithm_name = "RSASSA-PKCS1-V1_5"; // "RSA-PSS", "ECDSA"

    // WebCrypto
    let crypto = org.pkijs.getCrypto();
    if (typeof crypto == "undefined") {
        alert("No WebCrypto extension found");
        return;
    }

    pkcs10CSR.version = 0;
    pkcs10CSR.attributes = [];

    populateAttr(pkcs10CSR, 'C');
    populateAttr(pkcs10CSR, 'CN');
    populateAttr(pkcs10CSR, 'L');
    populateAttr(pkcs10CSR, 'O');
    populateAttr(pkcs10CSR, 'OU');

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
    }).catch(function (error) {
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
    }).catch(function (error) {
        alert("Error during exporting public key: " + error);
    }).then(function () {
        return crypto.exportKey("pkcs8", privateKey);
    }).then(function (pkcs8Privkey) {
        return [csr2pem(pkcs10CSR), privkey2pem(pkcs8Privkey)];
    }).catch(function (error) {
        alert("Error signing PKCS#10: " + error);
    });
}

function pem2pkcs12(cert,key){
    let fCert = forge.pki.certificateFromPem(cert);
    let fKey = forge.pki.privateKeyFromPem(key);
    let password = document.getElementById("password").value;
    let p12Asn1 = forge.pkcs12.toPkcs12Asn1(fKey, fCert, password,{algorithm:'3des'});
    // base64-encode p12
    let p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    return p12Der;
}

/* creates a PKCS10 CSR and signs it */
function getClientCert() {
    createPKCS10()
        .then(([csr, priv])=> {
            return Promise.all([post('cert.pem', csr), priv]);
        })
        .then(([pem,key])=> {
            let p12Der = pem2pkcs12(pem,key);
            let p12b64 = forge.util.encode64(p12Der);

            downloadP12B64('client.p12',p12b64);
            download('client.crt',[pem, key].join(''));
        })
}

/* promisify XHR req */
function post(url, str) {
    return new Promise(function (resolve, reject) {
        var req = new XMLHttpRequest();
        req.open('POST', url);
        req.setRequestHeader("Content-Type", "text/plain");

        req.onload = function () {
            if (req.status >= 200 && req.status < 300) {
                resolve(req.response);
            } else {
                reject(Error(req.statusText));
            }
        };

        req.onerror = function () {
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

/* Download PKCS#12 in Base64 */
function downloadP12B64(name, p12b64) {
    var a = document.createElement('a');
    a.setAttribute('href', 'data:application/x-pkcs12;base64,' + p12b64);
    a.setAttribute('download', name);
    //a.appendChild(doc if (document.createEvent) {

    if (document.createEvent) {
        var event = document.createEvent('MouseEvents');
        event.initEvent('click', true, true);
        a.dispatchEvent(event);
    }
    else {
        a.click();
    }
}
