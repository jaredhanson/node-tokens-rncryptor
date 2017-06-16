var RNCryptor = require('jscryptor');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;

    before(function() {
      keying = sinon.spy(function(q, cb){
        if (!q.recipient) {
          return cb(null, [ { secret: '12abcdef7890abcdef7890abcdef7890' } ]);
        }
        
        switch (q.recipient.id) {
        case 'https://api.example.com/':
          if (q.usage == 'sign') {
            return cb(null, [ { secret: 'API-90abcdef7890abcdef7890abcdef' } ]);
          } else {
            return cb(null, [ { secret: 'API-12abcdef7890abcdef7890abcdef' } ]);
          }
        }
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
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(112);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var decrypted = RNCryptor.Decrypt(token, '12abcdef7890abcdef7890abcdef7890');
          claims = JSON.parse(decrypted.toString());
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to audience', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
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
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'deriveKey',
          algorithms: [ 'pbkdf2' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(112);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function() {
          var decrypted = RNCryptor.Decrypt(token, 'API-12abcdef7890abcdef7890abcdef');
          claims = JSON.parse(decrypted.toString());
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience
    
    describe('encrypting to audience in key-based mode', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience, password: false }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/'
          },
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(88);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      // TODO: Implement decrypting using key-based decryption
      /*
      describe('verifying token', function() {
        var claims;
        before(function() {
          var decrypted = RNCryptor.Decrypt(token, 'API-12abcdef7890abcdef7890abcdef');
          claims = JSON.parse(decrypted.toString());
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
      */
    }); // encrypting to audience in key-based mode
    
  }); // using defaults
  
});
