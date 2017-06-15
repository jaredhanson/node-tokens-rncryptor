var RNCryptor = require('jscryptor');


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function rncryptor_unseal(sealed, cb) {
    var query  = {
      usage: 'deriveKey',
      algorithms: [ 'pbkdf2' ]
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // TODO: Implement support for checking multiple keys
      
      var key = keys[0];
      
      var decrypted = RNCryptor.Decrypt(sealed, key.secret);
      
      // TODO: Other payload formats (messagepack, etc)
      var claims = JSON.parse(decrypted);
      
      var tkn = {
        headers: {
        },
        claims: claims
      }
      return cb(null, tkn);
    });
  };
};
