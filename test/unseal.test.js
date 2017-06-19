/* global describe, it */

var setup = require('../lib/unseal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('unseal', function() {
  
  describe('using defaults', function() {
    var unseal, keying;
    
    describe('decrypting', function() {
      before(function() {
        keying = sinon.spy(function(q, cb){
          return cb(null, [ { secret: '12abcdef7890abcdef7890abcdef7890' } ]);
        });
      
        unseal = setup(keying);
      });
      
      var tkn;
      before(function(done) {
        var token = 'AwEAIcB0hzcLrasBYRFqr5btQgy7U6HA/F0++rjAphKh4QwbMMixoj9Lf0A0ht8wzO7L7sM2iAyqEVtzszpqOmKih0DT+KgjQFHCdtMfg+mGEA==';
        
        unseal(token, function(err, t) {
          tkn = t;
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
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ],
        });
      });
      
      it('should unseal token', function() {
        expect(tkn).to.be.an('object');
        expect(Object.keys(tkn)).to.have.length(2);
        
        expect(tkn).to.deep.equal({
          headers: {
          },
          claims: {
            foo: 'bar'
          }
        });
      });
    }); // decrypting
    
  }); // using defaults
  
});
