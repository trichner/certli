'use strict';
const CASigner = require('./casigner.js');
const express = require('express');
const basicAuth = require('basic-auth-connect');

const USER = 'admin';
const PASSWORD = '1234';

const app = express();

/* OPTIONAL: Protect with HTTP basic auth */
//app.use(basicAuth(USER, PASSWORD));

app.use(express.static(__dirname + '/public'));

app.post('/cert.pem', function (req, res) {
	res.set('Content-Type', 'text/plain');
  	let signer = new CASigner();
  	req.pipe(signer).pipe(res);
});


app.listen(3000, function () {
  console.log('Certli listening on port 3000!');
});

