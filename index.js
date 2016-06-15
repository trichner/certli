'use strict';
const CASigner = require('./casigner.js');
const express = require('express');
const conf = require('./conf.json');

const router = express.Router();
const app = express();

router.use(express.static(__dirname + '/public'));

router.post('/cert.pem', function (req, res) {
	res.set('Content-Type', 'text/plain');
  	let signer = new CASigner();
  	req.pipe(signer).pipe(res);
});

app.use(conf.prefix,router);
app.listen(conf.port, function () {
  console.log(`Certli listening on port ${conf.port}!`);
});

