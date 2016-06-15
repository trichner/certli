function stripPEM(pem){
    let lines = pem.split(/\r?\n/);
    let str = '';
    for(let l of lines){
        if(!l.startsWith('-')){
            str += l;
        }
    }
    return str;
}

function pems2pkcs12(certPEMStr, keyPEMStr, password) {
    keyPEMStr = stripPEM(keyPEMStr);
    certPEMStr = stripPEM(certPEMStr);
    // #region Initial variables
    var sequence = Promise.resolve();
    
    let keyLocalIDBuffer = new ArrayBuffer(4);
    let keyLocalIDView = new Uint8Array(keyLocalIDBuffer);

    org.pkijs.getRandomValues(keyLocalIDView)

    let certLocalIDBuffer = new ArrayBuffer(4);
    let certLocalIDView = new Uint8Array(certLocalIDBuffer);

    org.pkijs.getRandomValues(certLocalIDView)


    // #region "KeyUsage" attribute
    let bit_array = new ArrayBuffer(1);
    let bit_view = new Uint8Array(bit_array);

    bit_view[0] = bit_view[0] | 0x80;

    let key_usage = new org.pkijs.asn1.BITSTRING({
        value_hex: bit_array,
        unused_bits: 7
    });

    // #region Create simplified structires for certificate and private key
    let asn1 = org.pkijs.fromBER(str2ab(window.atob(certPEMStr)));
    let cert_simpl = new org.pkijs.simpl.CERT({schema: asn1.result});

    asn1 = org.pkijs.fromBER(str2ab(window.atob(keyPEMStr)));
    let pkcs8_simpl = new org.pkijs.simpl.PKCS8({schema: asn1.result});

    // #region Add "keyUsage" attribute
    pkcs8_simpl.attributes = [
        new org.pkijs.simpl.ATTRIBUTE({
            type: "2.5.29.15",
            values: [
                key_usage
            ]
        })
    ];

    // #region Put initial values for PKCS#12 structures
    var pkcs12 = new org.pkijs.simpl.PFX({
        parsedValue: {
            integrityMode: 0, // Password-Based Integrity Mode
            authenticatedSafe: new org.pkijs.simpl.pkcs12.AuthenticatedSafe({
                parsedValue: {
                    safeContents: [
                        {
                            privacyMode: 0, // "No-privacy" Protection Mode
                            value: new org.pkijs.simpl.pkcs12.SafeContents({
                                safeBags: [
                                    new org.pkijs.simpl.pkcs12.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.2",
                                        bagValue: new org.pkijs.simpl.pkcs12.PKCS8ShroudedKeyBag({
                                            parsedValue: pkcs8_simpl
                                        }),
                                        bagAttributes: [
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.2.840.113549.1.9.20", // friendlyName
                                                attrValues: [
                                                    new org.pkijs.asn1.BMPSTRING({value: "PKCS8ShroudedKeyBag from PKIjs"})
                                                ]
                                            }),
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.2.840.113549.1.9.21", // localKeyID
                                                attrValues: [
                                                    new org.pkijs.asn1.OCTETSTRING({value_hex: keyLocalIDBuffer})
                                                ]
                                            }),
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.3.6.1.4.1.311.17.1", // pkcs12KeyProviderNameAttr
                                                attrValues: [
                                                    new org.pkijs.asn1.BMPSTRING({value: "http://www.pkijs.org"})
                                                ]
                                            })
                                        ]
                                    })
                                ]
                            })
                        },
                        {
                            privacyMode: 1, // Password-Based Privacy Protection Mode
                            value: new org.pkijs.simpl.pkcs12.SafeContents({
                                safeBags: [
                                    new org.pkijs.simpl.pkcs12.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.3",
                                        bagValue: new org.pkijs.simpl.pkcs12.CertBag({
                                            parsedValue: cert_simpl
                                        }),
                                        bagAttributes: [
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.2.840.113549.1.9.20", // friendlyName
                                                attrValues: [
                                                    new org.pkijs.asn1.BMPSTRING({value: "CertBag from PKIjs"})
                                                ]
                                            }),
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.2.840.113549.1.9.21", // localKeyID
                                                attrValues: [
                                                    new org.pkijs.asn1.OCTETSTRING({value_hex: certLocalIDBuffer})
                                                ]
                                            }),
                                            new org.pkijs.simpl.cms.Attribute({
                                                attrType: "1.3.6.1.4.1.311.17.1", // pkcs12KeyProviderNameAttr
                                                attrValues: [
                                                    new org.pkijs.asn1.BMPSTRING({value: "http://www.pkijs.org"})
                                                ]
                                            })
                                        ]
                                    })
                                ]
                            })
                        }
                    ]
                }
            })
        }
    });
    // #endregion

    // #region Encode internal values for "PKCS8ShroudedKeyBag"
    sequence = sequence.then(
        function () {
            return pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.makeInternalValues({
                password: str2ab(password),
                contentEncryptionAlgorithm: {
                    name: "AES-CBC", // OpenSSL can handle AES-CBC only
                    length: 128
                },
                hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
                iterationCount: 100000
            });
        }
    );
    // #endregion

    // #region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes)
    sequence = sequence.then(
        function (result) {
            return pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
                safeContents: [
                    {
                        // Empty parameters for first SafeContent since "No Privacy" protection mode there
                    },
                    {
                        password: str2ab(password),
                        contentEncryptionAlgorithm: {
                            name: "AES-CBC", // OpenSSL can handle AES-CBC only
                            length: 128
                        },
                        hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
                        iterationCount: 100000
                    }
                ]
            });
        }
    );

    // #region Encode internal values for "Integrity Protection" envelope
    sequence = sequence.then(
        function () {
            return pkcs12.makeInternalValues({
                password: str2ab(password),
                iterations: 100000,
                pbkdf2HashAlgorithm: "SHA-256", // OpenSSL can not handle usage of PBKDF2, only PBKDF1
                hmacHashAlgorithm: "SHA-256"
            });
        }
    );

    // #region Save encoded data
    sequence = sequence.then(
        function () {
            var pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], {type: 'application/x-pkcs12'});
            var downloadLink = document.createElement("a");
            downloadLink.download = "pkijs_pkcs12.p12";
            downloadLink.innerHTML = "Download File";

            downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
            downloadLink.onclick = (event)=>{document.body.removeChild(event.target);};
            downloadLink.style.display = "none";
            document.body.appendChild(downloadLink);
            downloadLink.click();
        }
    );
}
