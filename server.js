
/**
 * Module dependencies
 */

var fs = require('fs');
var express = require('express');
var mongoose = require('mongoose');
var passport = require('passport');
var config = require('./config/env/production');
mongoose.Promise = require('bluebird');
var app = express();
var port = process.env.PORT || 8081;

// Connect to mongodb
var connect = function () {
  var options = { server: { socketOptions: { keepAlive: 1 } } };
  mongoose.connect(config.db, options);
};
connect();

mongoose.connection.on('error', console.log);
mongoose.connection.on('disconnected', connect);

// Bootstrap models
fs.readdirSync(__dirname + '/app/models').forEach(function (file) {
  if (~file.indexOf('.js')) require(__dirname + '/app/models/' + file);
});

// Bootstrap passport config
require('./config/passport')(passport, config);

// Bootstrap application settings
require('./config/express')(app, passport);

// Bootstrap routes
fs.readdirSync(__dirname + '/config/routes').forEach(function (file) {
  // console.log("file", file);
  if (~file.indexOf('.js'))
    require(__dirname + '/config/routes/' + file)(app, passport);
});
var listenPort = parseInt(port) + parseInt(process.env.NODE_APP_INSTANCE)
console.log('Express app started on port ' + 8081);
app.listen(8081);
