var crypto = require('crypto');
var querystring = require('querystring');

var swt = module.exports;

swt.parse = function (rawToken) {
	if (!rawToken) {
		return;
	};

	var attrs = querystring.parse(rawToken);

	if (Object.keys(attrs).length == 0) {
		return;
	};

	var profile = { claims: {} };

	for(var key in attrs) {
		var value = attrs[key];

		switch (key.toLowerCase()) {
			case 'audience':
				profile.audience = value;
				break;

			case 'expireson':
				var ticks = parseInt(value, 10);

				if (!isNaN(ticks)) {
					profile.expiresOn = new Date(ticks * 1000);
				};

				break;

			case 'issuer':
				profile.issuer = value;
				break;

			case 'hmacsha256':
				break;

			default:
				profile.claims[key] = value;
		}
	}

	return profile;
}

swt.validate = function(rawToken, options, cb) {

	if (!options.key) {
		cb(new Error('options.key is required.'));
		return;
	};

	var parts = rawToken.split('&HMACSHA256=');

	if (parts.length != 2) {
		cb(new Error('Invalid token format.'));
		return;
	};

	var profile = {};

	try {
		profile = swt.parse(rawToken);
	}
	catch (e) {
		cb(new Error('Invalid token format.'));
		return;
	}

	if (!options.bypassExpiration && new Date() > profile.expiresOn) {
		cb(new Error('Token is expired.'));
		return;
	};

	if (options.audience && options.audience != profile.audience) {
		cb(new Error('Invalid audience.'))
		return;
	};

	var signature = createHmac(parts[0], options.key);

	if (signature != decodeURIComponent(parts[1])) {
		cb(new Error('Invalid signature.'));
		return;
	};

	cb(null, profile);
}

swt.sign = function(attributes, options) {

	if (!options.key) {
		throw new Error('options.key is required!')
		return;
	};

	if (!options.issuer) {
		throw new Error('options.issuer is required!')
		return;
	};

	if (!options.audience) {
		throw new Error('options.audience is required!')
		return;
	};

	if (options.expiresInMinutes && (typeof options.expiresInMinutes != 'number' || isNaN(options.expiresInMinutes))) {
		options.expiresInMinutes = 1;
	};

	attributes = attributes || {};
	attributes.Audience = options.audience;
	attributes.Issuer = options.issuer;
	attributes.ExpiresOn = Math.round(new Date().getTime() / 1000 + options.expiresInMinutes * 60);

	var raw = querystring.stringify(attributes);

	var hmac = createHmac(raw, options.key);

	raw = raw + '&HMACSHA256=' + encodeURIComponent(hmac);
	return raw;
}

function createHmac(content, key) {
	return crypto.createHmac('RSA-SHA256', new Buffer(key, 'base64')
		.toString('binary'))
	.update(new Buffer(content, 'utf8'))
	.digest('base64');
}