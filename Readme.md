# Certli - Simple Client Certificates

Simple Client-Server App that generates a valid Client Certificate signed by the server.

One use-case is the replacement of HTTP Basic Authentication. Simply generate and install a certififcate
and never enter a password again.

The generated certificate is provided in PEM as well as in PKCS#12 format, which can be imported in
most browsers (tested in Chrome and Firefox).

## Screenshot
![Alt text](screenie.png?raw=true "Screenie")

## Basic Flow
1. Generate RSA keypair via WebCrypto API
2. Generate PKCS#10 certificate request containing public key
3. Let the server sign the request with `ca.pem`
4. Export the private key as PKCS#8
5. Combine the certificate with the private key
6. Export the bundle as PEM (\*.crt) as well as PKCS#12 (\*.p12)

## Setup
- install dependencies
- create `ca.pem`
- optional: configure Apache/Nginx proxy

### Install dependencies
```
sudo apt install nodejs-legacy npm openssl
npm install
```

### Create Certificate Authority (CA)

1. Generate a private key:
   ```
   openssl genrsa 2048 > ca.key
   ```
   
   Alternatively with password:
   ```
   openssl genrsa -des3 2048 > ca.key
   ```
   
2. Generate CA Certificate
   ```
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 > ca.crt
   ```
   
3. Merge CA Certificate and Key
   ```
   cat ca.key ca.crt > ca.pem
   ```
   
### Run the server
```
npm start
```
   
## Apache/Nginx Conf


### Nginx
Example virtual host configj.
```
server {
    listen 443;
    listen [::]:443;

    server_name n1b.ch;

    # setup TLS;
    ssl on;
    ssl_certificate /etc/nginx/certs/k42.ch/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/k42.ch/privkey.pem;

    # Cipher config
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH EDH+aRSA !RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS";
    ssl_dhparam /etc/nginx/tls/dhparam.pem;
    ssl_session_cache      shared:SSL:10m;
    ssl_session_timeout  10m;

    # Client certificate authentication
	ssl_client_certificate /etc/nginx/certli/ca.pem;
	ssl_verify_client on;

	root /usr/share/nginx/html/n1b.ch;
}

```

### Apache
Basic:
```
SSLVerifyClient require
SSLVerifyDepth 1
SSLCACertificateFile "conf/ssl.crt/ca.pem"
```


## Client Cert in CLI
```
openssl genrsa 2048 > client.key
openssl req -new -key client.key > client.csr

openssl x509 -req -days 365 -CA ca.pem -set_serial 1 < client.csr > client.crt

openssl pkcs12 -export -clcerts -in client.crt -inkey client.key > client.p12
```
