# Certli - Simple Client Certificates

Simple Client-Server App that generates a valid Client Certificate signed by the server.

One use-case is the replacement of HTTP Basic Authentication. Simply generate and install a certififcate and never enter a password again.


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

## Apache Conf