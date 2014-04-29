var assert = require('assert');
var swt = require('../lib');

var symmetricKey = 'your-symmetric-key';
var validAudience = 'your-scope';

describe('lib.index.parse', function() {
	it('Should parse SWT', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 60,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		var profile = swt.parse(token);

		assert.ok(profile);
		assert.ok(profile.claims);
		assert.equal('Leandro', profile.claims.name)
		assert.equal('http://nice-audience.com/', profile.audience);

		done();
	});

	it('Should not fail with invalid SWT', function(done) {
		var profile = swt.parse('adad=123123&ExpiresOn=lasldasd&');
		assert.ok(profile);
		assert.ok(profile.claims)
		done();
	});
})

describe('lib.index.validate', function () {
	it('Should fail with invalid token format', function(done) {
		swt.validate('adjdaksjd', { key: symmetricKey, bypassExpiration: true }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid token format.', err.message)
			done();
		})
	})

	it('Should fail with expired token', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: -1,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		swt.validate(token, { key: symmetricKey }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Token is expired.', err.message);
			done();
		})
	});

	it('Should fail with invalid audience', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 1,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		swt.validate(token, { key: symmetricKey, audience: 'http://anyother.com/' }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid audience.', err.message);
			done();
		})
	});

	it('Should fail with invalid signature', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 1,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		var hackedToken = token.replace('Leandro', 'John');

		swt.validate(hackedToken, { key: symmetricKey }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid signature.', err.message);
			done();
		})
	});

	it('Should validate SWT', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 1,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		swt.validate(token, { key: symmetricKey }, function(err, profile) {
			assert.ifError(err);

			assert.ok(profile.claims);
			done();
		})
	})

	it('Should validate SWT with audience', function(done) {

		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 10,
			issuer: 'http://issuer.com/'
		};

		var token = swt.sign(userInfo, options);

		swt.validate(token, { key: symmetricKey, audience: 'http://nice-audience.com/' }, function(err, profile) {
			assert.ifError(err);

			assert.ok(profile.claims);
			done();
		})
	})
})

describe('lib.index.sign', function () {
	it('Should sign a JWT', function (done) {
		var userInfo = {
			name: 'Leandro',
			age: 27
		};

		var options = {
			key: symmetricKey,
			audience: 'http://nice-audience.com/',
			expiresInMinutes: 61,
			issuer: 'http://issuer.com/'
		};

		var rawToken = swt.sign(userInfo, options);

		swt.validate(rawToken, { key: symmetricKey, audience: 'http://nice-audience.com/' }, function(err, profile) {
			assert.ifError(err);
			assert.ok(profile);
			assert.ok(profile.claims);
			assert.equal('Leandro', profile.claims.name)
			assert.equal(27, profile.claims.age);

			var hourLater = new Date();
			hourLater.setMinutes(hourLater.getMinutes() + 60);

			assert.ok(hourLater < profile.expiresOn);

			done();
		})
	})
})