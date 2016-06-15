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

/* convert string to arraybuffer */
function str2ab(str) {
  let buf = new ArrayBuffer(str.length); // 2 bytes for each char
  let bufView = new Uint8Array(buf);
  for (var i=0; i<str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
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
