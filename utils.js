
var jwt = require('jwt-simple');
var config = require('./config/env/production');
var mongoose = require('mongoose');
var https = require("https");
var http = require("http");
var fs = require('fs');
var nodemailer = require('nodemailer');
var handlebars = require('handlebars');
var crypto = require('crypto');
var xxtea = require('xxtea-node');

var smtpTransport = require('nodemailer-smtp-transport');
var transporter = nodemailer.createTransport({
    transport: 'ses', // loads nodemailer-ses-transport
    accessKeyId: config.aws.accessKeyId,
    secretAccessKey: config.aws.secretAccessKey,
    region: config.aws.region
});

var User = mongoose.model('User');
var AdminUser = mongoose.model('adminuser');

// function replaceAll(str, mapObj){
//     var regex = "";
//     Object.keys(mapObj).forEach(function(key) {
//         regex = regex + "\{\{" + key + "\}\}" + "|";
//     })
//
//     regex = regex.substring(0, regex.length - 1);
//
//     var re = new RegExp(regex,"gi");
//
//     console.log('Regex', re);
//     return str.replace(re, function(matched){
//         return mapObj[matched.substring(2, matched.length-2)];
//     });
// }

module.exports = {
    sendSuccessResponse: function (res, status, data, totalCount) {
        res.status(status);
        res.json({
            meta: {
                code: 0,
                currentDate: new Date()
            },
            data: data,
            totalCount: totalCount
        })
    },
    sendFailureResponse: function (res, status, errorCode, errorMessage, debugMessage, stack) {
        res.status(status);
        res.json({
            meta: {
                code: errorCode,
                errorMessage: errorMessage,
                debugMessage: debugMessage,
                currentDate: new Date(),
                stack: stack
            }
        })
    },
    ensureAuthenticated: function (req, res, next) {
        if (req.cookies.accesstoken) {
            var accessToken = req.cookies.accesstoken;
            try {
                var decoded = jwt.decode(accessToken, config.jwtTokenSecret);
                if (new Date(decoded.exp) <= Date.now()) {
                    module.exports.sendFailureResponse(res, 400, 1004, 'expiredToken', 'The access token has expired');
                } else {
                    User.findOne({ _id: decoded.iss }, function (err, user) {
                        if (err) {
                            module.exports.sendFailureResponse(res, 500, 1001, 'Database Failure', err.message);
                        } else if (!user) {
                            module.exports.sendFailureResponse(res, 403, 1005, 'Invalid token', 'Access token is invalid');
                        } else {
                            var userObject = user.toObject()
                            delete userObject.hashed_password;
                            delete userObject.salt;
                            userObject.accessToken = accessToken;
                            userObject.expiresIn = decoded.exp;
                            req.user = userObject;
                            next();
                        }
                    });
                }
            } catch (err) {
                console.log('err', err);
                module.exports.sendFailureResponse(res, 403, 1005, 'Invalid token', err.message);
            }
        } else {
            module.exports.sendFailureResponse(res, 400, 1004, 'No token', 'You are not logged in, please login.');
        }
    },
    ensureAdminAuthenticated: function (req, res, next) {
        if (req.cookies.accesstoken) {
            var accessToken = req.cookies.accesstoken;
            try {
                var decoded = jwt.decode(accessToken, config.jwtTokenSecret);
                if (new Date(decoded.exp) <= Date.now()) {
                    module.exports.sendFailureResponse(res, 400, 1004, 'expiredToken', 'The access token has expired');
                } else {
                    AdminUser.findOne({ _id: decoded.iss }, function (err, user) {
                        if (err) {
                            module.exports.sendFailureResponse(res, 500, 1001, 'Database Failure', err.message);
                        } else if (!user) {
                            module.exports.sendFailureResponse(res, 403, 1005, 'Invalid token', 'Access token is invalid');
                        } else {
                            var userObject = user.toObject()
                            delete userObject.hashed_password;
                            delete userObject.salt;
                            userObject.accessToken = accessToken;
                            userObject.expiresIn = decoded.exp;
                            req.user = userObject;
                            next();
                        }
                    });
                }
            } catch (err) {
                console.log('err', err);
                module.exports.sendFailureResponse(res, 403, 1005, 'Invalid token', err.message);
            }
        } else {
            module.exports.sendFailureResponse(res, 400, 1004, 'No token', 'You are not logged in, please login.');
        }
    },
    isAuthenticated: function (req, res, cb) {
        if (req.cookies.accesstoken) {
            try {
                var accessToken = req.cookies.accesstoken;
                var decoded = jwt.decode(accessToken, config.jwtTokenSecret);
                if (new Date(decoded.exp) <= Date.now()) {
                    console.log('not authenticated', req.cookies.accesstoken);
                    cb(false);
                } else {
                    console.log('is authenticated', req.cookies.accesstoken);
                    User.findOne({ _id: decoded.iss }, function (err, user) {
                        if (err) {
                            cb(false);
                        } else if (!user) {
                            cb(false);
                        } else {
                            var userObject = user.toObject()
                            delete userObject.hashed_password;
                            delete userObject.salt;
                            userObject.accessToken = accessToken;
                            userObject.expiresIn = decoded.exp;
                            req.user = userObject;
                            cb(true);
                        }
                    });
                }
            } catch (err) {
                console.log('err', err);
                cb(false);
            }
        } else {
            cb(false);
        }
    },
    isAuthenticatedProfile: function (req, res, next) {
        if (req.headers.accesstoken) {
            var userDetailString = module.exports.decryptStringUsingXXtea(req.headers.accesstoken);
            var requestMethod = req.method;

            if (userDetailString && JSON.parse(userDetailString).deviceId == req.body.deviceId && (requestMethod == 'POST' || requestMethod == "PUT")) {
                console.log('AUTHENTICATED', req.body.deviceId);
                req.deviceId = JSON.parse(userDetailString).deviceId
                next();
            } else if (userDetailString && JSON.parse(userDetailString).deviceId && requestMethod == 'GET') {
                console.log('AUTHENTICATED GET REQUEST', JSON.parse(userDetailString).deviceId)
                req.deviceId = JSON.parse(userDetailString).deviceId
                next();
            } else {
                console.log('UNAUTHORIZED', ' error unauthorized user', req.body, userDetailString);
                module.exports.sendFailureResponse(res, 401, 1001, "You are not authorized to access this profile");
            }
        } else {
            module.exports.sendFailureResponse(res, 401, 1001, "You are not authorized to access this profile");
        }
    },
    request: function (options, cb) {
        var prot = options.port == 443 ? https : http;
        var post_data = options.data;
        delete options.data;

        var req = prot.request(options, function (res) {
            var output = '';
            console.log(options.host + ':' + res.statusCode);
            res.setEncoding('utf8');

            res.on('data', function (chunk) {
                output += chunk;
            });

            res.on('end', function () {
                var obj = JSON.parse(output);
                cb(null, res.statusCode, obj);
            });
        });

        if (post_data) {
            req.write(post_data);
        }

        req.on('error', function (err) {
            cb(err);
        });

        req.end();
    },
    getDateFileName: function () {
        var currentDate = new Date();

        var day = currentDate.getDate();
        var month = currentDate.getMonth() + 1;
        var year = currentDate.getFullYear();

        return year + '-' + month + '-' + day;
    },
    sendEmail: function (type, user, order) {
        var path = "";
        var subject = "";
        var replacements = {
            name: user.firstName,
            product_name: "Restaurant City",
            sender_name: config.email.sender,
            product_address_line1: "Address One",
            product_address_line2: "Address Two"
        }
        switch (type) {
            case 'welcome': {
                path = config.email.templates.welcome.path;
                subject = config.email.templates.welcome.subject;
                replacements['action_url'] = config.baseUrl + config.apiPrefix + 'user/verify?verificationToken=' + user.verificationToken;
                break;
            }
            case 'receipt': {
                path = config.email.templates.receipt.path;
                subject = config.email.templates.receipt.subject;
                replacements['date'] = new Date().toDateString();
                replacements['invoice_id'] = "fsdfdsfsdf";
                replacements['invoice_details'] = [
                    {
                        description: "Test product 1",
                        amount: 100
                    },
                    {
                        description: "Test product 2",
                        amount: 100
                    }
                ];
                replacements['total'] = 200;
                break;
            }
            case 'resetPassword': {
                path = config.email.templates.resetPassword.path;
                subject = config.email.templates.resetPassword.subject;
                replacements['action_url'] = 'http://cms.nayarkody.site/#!/resetpage/' + user.resetClickToken;
                break;
            }
        }
        module.exports.readHTMLFile(path, function (err, source) {
            if (err) {
                console.log('error reading html file', err);
            } else {
                var template = handlebars.compile(source);
                var html = template(replacements);

                var mailOptions = {
                    from: config.email.sender, // sender address
                    to: user.email, // list of receivers
                    subject: subject, // Subject line
                    html: html // html body
                };
                transporter.sendMail(mailOptions, function (err, info) {
                    if (err) {
                        return console.log("error sending mail to user", err);
                    }
                    console.log('Message sent: ' + info);
                });
            }
        })
    },
    readHTMLFile: function (path, callback) {
        fs.readFile(path, { encoding: 'utf-8' }, function (err, html) {
            if (err) {
                throw err;
                callback(err);
            }
            else {
                callback(null, html);
            }
        });
    },
    generateRandomToken: function () {
        return crypto.randomBytes(64).toString('hex');
    },
    encryptStringUsingXXtea: function (string) {
        var encryptData = xxtea.encrypt(xxtea.toBytes(string), xxtea.toBytes(config.encryptionKey));
        var encodedString = new Buffer(encryptData).toString('base64');
        return encodedString;
    },
    decryptStringUsingXXtea: function (string) {
        try {
            var decryptData = xxtea.toString(xxtea.decrypt(string, xxtea.toBytes(config.encryptionKey)));
            return decryptData;
        } catch (e) {
            return "";
        }
    },
    randomNameGenerator: function () {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (var i = 0; i < 5; i++)
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        return text;
    }
}


// var string = JSON.stringify({deviceId: "4eb90458d48f47dc"})
// var encryptedString = module.exports.encryptStringUsingXXtea(string)
// console.log(encryptedString);
// console.log(module.exports.decryptStringUsingXXtea("OZA5eQkz9jE8FSeD+ue8fn6gohvUCYRHX/1fWlhm9XS2OtuGPBGZZ41EFQvKQKF2Tsy4W12ZEAXIb4nUUfVBIu+DdErEOLDAt4m+Gv0my4R4NWk9lNG+QjitQwjGCH4uDh5FuMCm99kgyEAKbITH+VFVgXaiJGNMQpCoBeM8SmG9+nFSO0eaWvIrrM6kTnnG3ROrBnpMJVPlKHg55KDG/E9fCiNen7obmiibi/XugoOd3bCaiOmJbqZSDjbh4enCAMjGNZTuqmF7NmZd8fe17A=="));
