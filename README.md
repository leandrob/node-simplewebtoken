Simple Web Token Library
=============
simplewebtoken is a simple module that allows you to parse, validate and sign security assertions in SWT format. It is based on this specification http://msdn.microsoft.com/en-us/library/windowsazure/hh781551.aspx.

## Installation

```bash
$ npm install simplewebtoken
```

## Usage

### swt.parse(rawToken)

`rawToken` is the SWT token in string format, without decoding.

Parses the `rawToken` without validating signature, expiration and audience. It allows you to get information from the token like the Issuer name in order to obtain the right key to validate the token in a multi-providers scenario.

```javascript

var swt = require('simplewebtoken');

var profile = swt.parse(rawToken);

```

`profile` object will have this structure:

* `issuer` (String) is the issuer name, contained in the Issuer property of the token.
* `audience` (String) is the Audience specified in the token.
* `expiresOn` (Date) is the Date and Time when the token expires.
* `claims` (Object) Will contain a key-value json object with user information.

### swt.validate(rawToken, options, cb)

`rawToken` is SWT in string format.

`options`:

* `key` is the key used to validate the signature.
* `audience` (optional). If it is included audience validation will take place.
* `bypassExpiration` (optional). This flag indicates expiration validation bypass (useful for testing, not recommended in production environments);

```javascript

var swt = require('simplewebtoken');

var options = {
	key: 'key-used',
	audience: 'http://myservice.com/'
}

swt.validate(rawToken, options, function(err, profile) {
	// err

	var issuer = profile.issuer;
	var claims = profile.claims;
});

```

### swt.sign(rawToken, options)

`rawToken` is SWT in string format.

`options`:

* `key` (String) is the key that will be used to sign the token.
* `audience` (String) is the audience for which the toke will be signed.
* `issuer` (String) is the name of the issuer.
* `expiresInMinutes` (optional) (Number) is the number of minutes since the token is signed in which the token is valid. 


All parameters are required, except for `expiresInMinutes` which default value is 1 minute.

## Tests

### Configure test/lib.index.js

In order to run the tests you must configure `lib.index.js` with these variables:

```javascript

var token = "a-valid-but-expired-token-here";
var symmetricKey = 'your-symmetric-key';
var validAudience = 'your-scope';

```

To run the tests use:

```bash
$ npm test
```

## License

MIT




