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
    
    console.log('SEAL IT!');
    console.log(claims)
    
    var query  = {
      usage: 'deriveKey',
      recipient: audience[0],
      algorithms: [ 'pbkdf2' ]
    }
    
    keying(query, function(err, keys) {
      
      var key = keys[0];
      
      // TODO: Other payload formats (messagepack, etc)
      var payload = JSON.stringify(claims);
      
      console.log('ENCRYPT');
      console.log(payload);
      console.log(key);
      
      var token = RNCryptor.Encrypt(payload, key.secret);
      console.log(token);
      
      return cb(null, token);
    });
  };
};
