var expect  = require('expect.js');
const sinon = require('sinon');

describe('The s2JWTExtractor class ', function() {

    var instance, jwt;

    before(() => {
        instance = require('../src/index');
        jwt      = require('jsonwebtoken');
    });

    describe('when extracting jwt', function() {

        it('should return an error if the JWT data is null', function(done) {

            let expectedError = 'INVALID_JWT';

            instance.extract(null, null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the JWT data is undefined', function(done) {

            let expectedError = 'INVALID_JWT';

            instance.extract(undefined, null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the JWT data is empty', function(done) {

            let expectedError = 'INVALID_JWT';

            instance.extract('', null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the public key is null', function(done) {

            let expectedError = 'INVALID_PUBKEY';

            instance.extract('ANY_JWT', null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the public key is undefined', function(done) {

            let expectedError = 'INVALID_PUBKEY';

            instance.extract('ANY_JWT', null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the public key is empty', function(done) {

            let expectedError = 'INVALID_PUBKEY';

            instance.extract('ANY_JWT', null, null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the application name is null', function(done) {

            let expectedError = 'INVALID_APPNAME';

            instance.extract('ANY_JWT', 'ANY_PUBKEY', null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the application name is undefined', function(done) {

            let expectedError = 'INVALID_APPNAME';

            instance.extract('ANY_JWT', 'ANY_PUBKEY', null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the application name is empty', function(done) {

            let expectedError = 'INVALID_APPNAME';

            instance.extract('ANY_JWT', 'ANY_PUBKEY', null, function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if JWT data is invalid', function(done) {

            let expectedError = 'JsonWebTokenError: jwt malformed';

            instance.extract('ANY_JWT', 'ANY_PUBKEY', 'ANY_APPNAME', function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                done();
            });
        });

        it('should return an error if the app requested is not authorized', function(done) {

            let expectedError = 'INVALID_JWT_DATA';

            jwtStub = sinon.stub(jwt, 'verify');
            jwtStub.callsArgWith(3, null, null);

            instance.extract('ANY_JWT', 'ANY_PUBKEY', 'ANY_APPNAME', function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();

                jwtStub.restore();
                done();
            });
        });

        it('should return an error if the decoded data hasnt app key', function(done) {

            let expectedError = 'INVALID_JWT_APPS';

            jwtStub = sinon.stub(jwt, 'verify');
            jwtStub.callsArgWith(3, null, 'ANY_DECODED');

            instance.extract('ANY_JWT', 'ANY_PUBKEY', 'ANY_APPNAME', function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                jwtStub.restore();
                done();
            });
        });

        it('should return an error if the application is not authorized', function(done) {

            let expectedError = 'APP_UNAUTHORIZED';

            jwtStub = sinon.stub(jwt, 'verify');
            jwtStub.callsArgWith(3, null, {apps: 'OTHER_APPNAME'});

            instance.extract('ANY_JWT', 'ANY_PUBKEY', 'ANY_APPNAME', function(error, success){
                expect(error).to.eql(expectedError);
                expect(success).not.to.be.ok();
                jwtStub.restore();
                done();
            });
        });

        it('should return the decoded data if the everything is ok', function(done){

            let jwtDecodedData = {
                apps: {
                    datahub: true,
                    reports: true,
                    pay: {
                        contract: {
                            amount_per_transaction: 0,
                            tx_adm: 499,
                            tx_canc: 499
                        }
                        
                    },
                    wallet: {
                        bank_data: {
                            account       : '99999',
                            account_digit : '9',
                            agency        : '9999',
                            agency_digit  : '9',
                            bank          : '999'
                        },
                        contract: {
                            cnpj                  : '99999999999999',
                            gateway_integration   : true,
                            legal_name            : 'TEST LEGAL NAME',
                            maturity              : 30,
                            name                  : 'LEGAL',
                            time_zone             : 'America/Cuiaba',
                            withdrawal_fee_amount :  1000
                        }
                    },
                },
                contract_id: 'ANY_UNIQUE_TOKEN'
            }

            let expectedData = {
                appData: {
                    bank_data: {
                        account       : '99999',
                        account_digit : '9',
                        agency        : '9999',
                        agency_digit  : '9',
                        bank          : '999'
                    },
                    contract: {
                        cnpj                  : '99999999999999',
                        gateway_integration   : true,
                        legal_name            : 'TEST LEGAL NAME',
                        maturity              : 30,
                        name                  : 'LEGAL',
                        time_zone             : 'America/Cuiaba',
                        withdrawal_fee_amount :  1000
                    }
                },
                contract_id: 'ANY_UNIQUE_TOKEN'
            }

            jwtStub = sinon.stub(jwt, 'verify');
            jwtStub.callsArgWith(3, null, jwtDecodedData);

            instance.extract('ANY_JWT', 'ANY_PUBKEY', 'wallet', function(error, success){
                expect(error).not.to.be.ok();
                expect(success).to.eql(expectedData);
                jwtStub.restore();
                done();
            });
        });

    });
});
