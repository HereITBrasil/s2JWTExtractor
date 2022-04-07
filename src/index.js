const jwt = require('jsonwebtoken');
const isEmpty   = require('is-empty');

var s2JWTExtractor = (function () {

    return {
        extract: function(jwtData, pubkey, appname, callback){

            if (isEmpty(jwtData)) {
                return callback('INVALID_JWT');
            }

            if (isEmpty(pubkey)) {
                return callback('INVALID_PUBKEY');
            }

            if (isEmpty(appname)) {
                return callback('INVALID_APPNAME');
            }

            jwtOptions = {
                format: 'PKCS8',
                algorithms: ['RS256']
            }

            jwt.verify(jwtData, pubkey, jwtOptions, function (error, decoded) {

                if (!isEmpty(error)) {
                    return callback(error.toString());
                }

                if (isEmpty(decoded)) {
                    return callback('INVALID_JWT_DATA');
                }

                if (isEmpty(decoded.apps)) {
                    return callback('INVALID_JWT_APPS');
                }

                if (!decoded.apps.hasOwnProperty(appname)) {
                    return callback('APP_UNAUTHORIZED');
                }

                var appData = decoded.apps[appname];

                var extractedData = {
                    appData: appData,
                    contract_id: decoded.contract_id
                };

                callback(null, extractedData);
            });
        }
    }
})();

module.exports = s2JWTExtractor;

