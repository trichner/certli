'use strict';
const spawn = require('child-process-promise').spawn;
const Transform = require('stream').Transform;

class CASigner extends Transform{
	constructor(options){
		super(options);
		options = options || {};
		let caFile = options.caFile || 'ca.pem';
		let args = ['x509', '-req', '-days', '3650', '-CA', caFile,'-CAcreateserial', '-CAserial', 'ca.seq'];
		
		if(options.caPassword){
			args.push('-passin');
			args.push(`pass:${options.caPassword}`);
		}

		let promisedChild = spawn('openssl',args, { capture: [ 'stdout', 'stderr' ]})
		this.child = promisedChild.childProcess;
		let self = this;
		promisedChild.then((result)=>{
			self.push(result.stdout);
			self.emit('end');
		})
		.catch((err)=>{
			self.emit('error',err);
		})
	}

	_transform(data, encoding, callback){
		this.child.stdin.write(data);
		
	}

}

module.exports = CASigner;
