var RNCryptor = require('jscryptor');


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
    
    var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal fernet tokens for multiple recipients'));
    }
    
    
    var query  = {
      usage: 'deriveKey',
      recipient: audience[0],
      algorithms: [ 'pbkdf2' ]
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // TODO: Other payload formats (messagepack, etc)
      var payload = JSON.stringify(claims);
      
      var key = keys[0];
      var token = RNCryptor.Encrypt(payload, key.secret);
      
      return cb(null, token);
    });
  };
};
