var crypto = require('crypto');

var JWT = {
	decode: function(jwt, key, verify) {
		verify = typeof verify === 'undefined' ? true : verify;
		var tks = jwt.split('.');
		if(tks.length != 3)
			throw new Error('Wrong number of segments.');
		var header = JSON.parse(JWT.urlsafeB64Decode(tks[0]));
		if(null === header)
			throw new Error('Invalid segment encoding');
		var payload = JSON.parse(JWT.urlsafeB64Decode(tks[1]));
		if(null === payload)
			throw new Error('Invalid segment encoding');
		if(verify) {
			if(!header.alg)
				throw new Error('Empty algorithm');
			if(JWT.urlsafeB64Decode(tks[2]) != JWT.sign([tks[0], tks[1]].join('.'), key, header.alg))
				throw new Error('Signature verification failed');
		}
		return payload;
	},
	encode: function(payload, key, algo) {
		algo = algo || 'HS256';
		var header = {
				typ: 'JWT',
				alg: algo
			},
			segments = [
				JWT.urlsafeB64Encode(JSON.stringify(header)),
				JWT.urlsafeB64Encode(JSON.stringify(payload))
			],
			signing_input = segments.join('.'),
			signature = JWT.sign(signing_input, key, algo);

		segments.push(JWT.urlsafeB64Encode(signature));
		return segments.join('.');
	},
	sign: function(msg, key, method) {
		method = method || 'HS256';
		var methods = {
			HS256: 'sha256',
			HS512: 'sha512'
		};
		if(!methods[method])
			throw new Error('Algorithm not supported');
		return crypto.createHmac(methods[method], key).update(msg).digest('binary');
	},
	urlsafeB64Decode: function(str) {
        while(str.length%4 != 0 ) {
            str += "=";
        }
        return urlsafeDecode64(str);
	},
	urlsafeB64Encode: function(str) {
		return urlsafeEncode64(str);
	}
};

// base64.js - Base64 encoding and decoding functions
//
// Copyright (c) 2007, David Lindquist <david.lindquist@gmail.com>
// Released under the MIT license
//
// Modified by TJ Holowaychuk for CommonJS module support.
// Modified by Ben Weaver to use any alphabet.

var encode64 = encoder('+/');
var decode64 = decoder('+/');
var urlsafeEncode64 = encoder('-_');
var urlsafeDecode64 = decoder('-_');

function encoder(extra) {
  var chars = alphabet(extra);

  return function(str) {
    str = str.toString();
    var encoded = [];
    var c = 0;
    while (c < str.length) {
      var b0 = str.charCodeAt(c++);
      var b1 = str.charCodeAt(c++);
      var b2 = str.charCodeAt(c++);
      var buf = (b0 << 16) + ((b1 || 0) << 8) + (b2 || 0);
      var i0 = (buf & (63 << 18)) >> 18;
      var i1 = (buf & (63 << 12)) >> 12;
      var i2 = isNaN(b1) ? 64 : (buf & (63 << 6)) >> 6;
      var i3 = isNaN(b2) ? 64 : (buf & 63);
      encoded[encoded.length] = chars.charAt(i0);
      encoded[encoded.length] = chars.charAt(i1);
      encoded[encoded.length] = chars.charAt(i2);
      encoded[encoded.length] = chars.charAt(i3);
    }
    return encoded.join('');
  };
}

function decoder(extra) {
  var chars = alphabet(extra),
      invalid_char = new RegExp('[^' + regexp_escape(chars) + ']');

  return function(str) {
    var invalid = {
      strlen: (str.length % 4 != 0),
      chars:  invalid_char.test(str),
      equals: (/=/.test(str) && (/=[^=]/.test(str) || /={3}/.test(str)))
    };
    if (invalid.strlen || invalid.chars || invalid.equals)
      throw new Error('Invalid base64 data');
    var decoded = [];
    var c = 0;
    while (c < str.length) {
      var i0 = chars.indexOf(str.charAt(c++));
      var i1 = chars.indexOf(str.charAt(c++));
      var i2 = chars.indexOf(str.charAt(c++));
      var i3 = chars.indexOf(str.charAt(c++));
      var buf = (i0 << 18) + (i1 << 12) + ((i2 & 63) << 6) + (i3 & 63);
      var b0 = (buf & (255 << 16)) >> 16;
      var b1 = (i2 == 64) ? -1 : (buf & (255 << 8)) >> 8;
      var b2 = (i3 == 64) ? -1 : (buf & 255);
      decoded[decoded.length] = String.fromCharCode(b0);
      if (b1 >= 0) decoded[decoded.length] = String.fromCharCode(b1);
      if (b2 >= 0) decoded[decoded.length] = String.fromCharCode(b2);
    }
    return decoded.join('');
  };
}


/// --- Aux

function alphabet(extra) {
  return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    + extra
    + '=';
}

function regexp_escape(expr) {
  return expr.replace(/([\^\$\/\.\*\-\+\?\|\(\)\[\]\{\}\\])/, '\\$1');
}


module.exports = JWT;
