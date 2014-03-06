var assert = require('assert');
var swt = require('../lib');

var token = "a-valid-but-expired-token-here";
var symmetricKey = 'your-symmetric-key';
var validAudience = 'your-scope';

describe('Parse', function() {
	it('Should parse SWT', function(done) {
		var profile = swt.parse(token);

		assert.ok(profile);
		assert.ok(profile.claims);
		assert.equal('kidozen.com', profile.claims['http://schemas.kidozen.com/domain'])
		assert.equal('http://tasks.armonia.kidocloud.com/', profile.audience);
		assert.ok(new Date(1394058708 * 1000).toString(), profile.expiresOn.toString());

		done();
	});

	it('Should not fail with invalid SWT', function(done) {
		var profile = swt.parse('adad=123123&ExpiresOn=lasldasd&');
		assert.ok(profile);
		assert.ok(profile.claims)
		done();
	});
})

describe('Validate', function () {
	it('Should fail with invalid token format', function(done) {
		swt.validate('adjdaksjd', { key: symmetricKey, bypassExpiration: true }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid token format.', err.message)
			done();
		})
	})

	it('Should fail with expired token', function(done) {
		swt.validate(token, { key: symmetricKey }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Token is expired.', err.message);
			done();
		})
	});

	it('Should fail with invalid audience', function(done) {
		swt.validate(token, { key: symmetricKey, bypassExpiration: true, audience: 'http://anyother.com/' }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid audience.', err.message);
			done();
		})
	});

	it('Should fail with invalid signature', function(done) {

		var hackedToken = token.replace('armonia%40kidozen.com', 'lean%40kidozen.com');

		swt.validate(hackedToken, { key: symmetricKey, bypassExpiration: true }, function(err, profile) {
			assert.ok(err);
			assert.ok(!profile);
			assert.equal('Invalid signature.', err.message);
			done();
		})
	});

	it('Should validate SWT', function(done) {
		swt.validate(token, { key: symmetricKey, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);

			assert.ok(profile.claims);
			done();
		})
	})

	it('Should validate SWT with audience', function(done) {
		swt.validate(token, { key: symmetricKey, bypassExpiration: true, audience: validAudience }, function(err, profile) {
			assert.ifError(err);

			assert.ok(profile.claims);
			done();
		})
	})
})

describe('Sign', function () {
	it('Should sign a SWT', function (done) {
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

		var rawToken = swt.sign(userInfo, options);

		swt.validate(rawToken, { key: symmetricKey, audience: 'http://nice-audience.com/' }, function(err, profile) {
			assert.ifError(err);
			assert.ok(profile);
			assert.ok(profile.claims);
			assert.equal('Leandro', profile.claims.name)
			assert.equal(27, profile.claims.age);

			done();
		})
	})
})