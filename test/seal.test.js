var RNCryptor = require('jscryptor');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;

    before(function() {
      keying = sinon.spy(function(q, cb){
        return cb(null, [ { secret: 'RS1-12abcdef7890' } ]);
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting to self', function() {
      var token;
      before(function(done) {
        seal({ foo: 'bar' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: undefined,
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(112);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var decrypted = RNCryptor.Decrypt(token, 'RS1-12abcdef7890');
          claims = JSON.parse(decrypted.toString());
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
  }); // using defaults
  
});
