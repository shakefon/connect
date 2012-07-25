/*!
 * Connect - xss
 * Copyright(c) 2011 Sencha Inc.
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var utils = require('../utils');

/**
 * Anti XSS:
 *
 * XSS protection middleware.
 *
 * Filters requests to remove common XSS attack techniques. Allows specification of regex patterns to extend ability.
 *
 * The default `filter` function checks req.originalUrl to detect XSS attacks and by default, sanitizes the value.
 *
 * Options:
 *
 *    - `filter` a function accepting the request, inspecting the original url
 *    - `block` boolean value, determing whether to block the request (true) or sanitize the requested URL (false)
 *    - `patterns` array of regex patterns to match against, to extend coverage to further XSS signatures
 *
 * @param {Object} options
 * @api public
 */

 module.exports = function xss(options) {
  var options = options || {}
    , filter = options.filter || defaultFilter
    , block = options.block || false
    , patternAppend = options.patternAppend || false
    , patterns = patternAppend ? (defaultPatterns.concat(options.patterns || [])) : (options.patterns || defaultPatterns);

  return function(req, res, next){

    req = filter(req, patterns);

    if (block && xssPresent) {
      xssPresent = false;
      return next(utils.error(400));      
    } 
    
    next();

  }
};

var defaultPatterns = [/(alert\()|([<|%3C]\/?script)|([<|%3C]iframe)|(src=)/gi]
  , xssPresent = false;

// NEED TO CHECK req.body if present too, and make sure bodyParser comes first so we can stop POST xss attacks

/**
 * Default filter function, checking the `req.originalUrl` for patterns matching common XSS attacks
 *
 * @param {IncomingMessage} req
 * @param {Array} patterns
 * @return {IncomingMessage} req
 * @api private
 */

function defaultFilter(req, patterns) {
  var hasXss = false
    , xssPatterns = defaultPatterns.concat(patterns)
    , i = xssPatterns.length;
  while (i--) {
    var p = xssPatterns[i],
        m = req.originalUrl.match(p);

    if (m) {
      req.originalUrl = req.originalUrl.replace(m[0], "");
      xssPresent = true;
    }
  }
  return req;
}