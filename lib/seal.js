var RNCryptor = require('jscryptor')
  , crypto = require('crypto');


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function rncryptor_seal(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    var password = options.password !== undefined ? options.password : true;
    
    var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal fernet tokens for multiple recipients'));
    }
    
    
    var query = password ? {
      usage: 'deriveKey',
      recipient: audience[0],
      algorithms: [ 'pbkdf2' ]
    } : {
      usage: 'encrypt',
      recipient: audience[0],
      algorithms: [ 'aes256-cbc' ]
    };
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // TODO: Other payload formats (messagepack, etc)
      var payload = JSON.stringify(claims);
      
      var key = keys[0];
      
      if (password) {
        // Operating in the (default) password-based mode, where encryption and
        // signing keys are derived from a single shared secret.
        var token = RNCryptor.Encrypt(payload, key.secret);
        return cb(null, token);
      } else {
        // Operating in key-based mode, where encryption and signing are done
        // with specific shared secrets.
        
        // The encryption key has been obtained, query for the signing key.
        var query  = {
          usage: 'sign',
          recipient: audience[0],
          algorithms: [ 'hmac-sha256' ]
        }
      
        keying(query, function(err, signingKeys) {
          if (err) { return cb(err); }
          
          var signingKey = signingKeys[0];
          var iv = crypto.randomBytes(16);
          
          var token = RNCryptor.EncryptWithArbitraryKeys(payload, key.secret, signingKey.secret, iv);
          return cb(null, token);
        });
      }
    });
  };
};
