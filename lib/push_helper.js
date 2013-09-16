var url = require('url'),
  util = require('util'),
  querystring= require('querystring');

function return_http_error(code) {
  var err = new Error(http.STATUS_CODES[code]);
  err.status = code;
  return err;
}

// simple constructor
exports.PuSHHelper = function(){ };

// Public: This method is used as a final middleware to handle the verification 
//         request that the pubsubhubbub server sends to the
//         subscribing endpoint.
//
//
// verify_token - (optional) the token used to verify the handshake
//
// Examples:
//
//              Here's a sample express.js route that uses this method:
//
//              app.get('/instagram/realtime', PuSHHelper.handshake('SOME_TOKEN'));
//
// Returns: Nothing directly. Will call the callback if defined. Otherwise, 
//          it will write and end() the response.
exports.PuSHHelper.handshake = function(verify_token) {



  return function(request, response, next) {
    var body, headers, parsedRequest;
    parsedRequest = url.parse(request.url, true);
    
    // Flickr is odd about this, doesn't use the hub. prefix.
    var hub_mode = parsedRequest['query']['hub.mode'] || parsedRequest['query']['mode'];
    var hub_challenge = parsedRequest['query']['hub.challenge'] || parsedRequest['query']['challenge'];
    var hub_verify_token = parsedRequest['query']['hub.verify_token'] || parsedRequest['query']['verify_token'];

    var is_verified = false;
    
    // console.log("hub_mode: " + hub_mode + " hub_challenge: " + hub_challenge);
    if ((hub_verify_token !== null) && (verify_token !== undefined && verify_token !== null)) {
      
      if (hub_verify_token == verify_token) {
        is_verified = true;
      }

    } else {
      is_verified = true;
    }

    if (is_verified === true && hub_mode === 'subscribe' && (hub_challenge !== null) && hub_challenge.length > 0) {
      body = hub_challenge;
      headers = {
        'Content-Length': body.length,
        'Content-Type': 'text/plain'
      };
      response.writeHead(200, headers);
      response.write(body);
    } else {
      response.writeHead(400);
    }
    return response.end();
  };


};



// Public: This method is used when your app handles a PuSH notification
//          from the source server. It validates that the request matches the
//          x-hub-signature sent with the request. It must be used in conjunction
//          with the middleware below.
//
// request - The rest object from the http server request handler
// secret  - The secret is an endpoint specific value used to generate the HMAC digest
//           for Instagram or FB, it's the client secret part of the keys, for example.
//
//              Note: this code is heavily inspired by the Instagram-node-lib project
//              almost exactly from their subscription class.
//
// Examples:
//
//            app.post('/instagram/realtime', PuSHHelper.check_signature, function(req, res){
//              console.log("Received & verified a notification");
//            });
//
//
// Returns: a 204 if the signature fails, or allows the middleware to continue.
exports.PuSHHelper.check_signature = function(request, response, next) {
  // console.log("calculated-signature: " + request["calculated-signature"]);

  // console.log("checking body-signature");
  if (request["body-signature"] !== undefined && request["body-signature"] !== null) {
    request["calculated-signature"] = request["body-signature"].digest(encoding = 'hex');
  } else {
    // this means our code didn't work... shouldn't get here.
    console.error("No body-signature found. Likely misconfigured. Is signature_calculator in the middleware chain before this and does some other middleware call wait for the request stream to end (e.g. bodyParser)?");
    return next(500);
  }

  if (request["calculated-signature"] !== undefined && request["calculated-signature"] !== null) {
    // console.log("submitted-signature: " + request.headers["x-hub-signature"]);
    var submitted_signature = request.headers['x-hub-signature'];
    if ((/^sha1=/i).test(submitted_signature)) {
      submitted_signature = submitted_signature.slice(5);
    }
    if (request["calculated-signature"] != submitted_signature) {
      // this is the weird thing. We will write and end the response here.
      // but, spec says to return a 2XX. Specifically:
      //
      // "If the signature does not match, subscribers MUST still return 
      // a 2xx success response to acknowledge receipt, but locally ignore
      // the message as invalid."
      console.log("ERROR");
      response.writeHead(204, { 'x-hub-error': "Unable to verify signature" });
      response.end();
      return false;
    } else {
      // we're good to go, call the next middleware.
      // console.log("calling the next middleware");
      return next();
    }
  } else {
    // something went wrong or this is user error. The middleware should only be
    // used in contexts where you know you need it.
    // 
    return next(500);
  }
};

// Public: This is a middleware that will stream in the request and calculate
//          the HMAC digest on the fly. This should be slightly more
//          memory efficient for most requests. It calculates only if the
//          x-hub-signature is detected.
//
//          See the comments inline in the code for details.
//
// secret  - The secret is an endpoint specific value used to generate the HMAC digest
//           for Instagram or FB, it's the client secret part of the keys, for example.
// route   - (optional) a route string that represents a regex pattern. Doesn't support
//           all the route options yet.
// save_body - (optional) a boolean that tells this filter to set rawBody (defaults to false)
//
//
//              Note: this code is taken from the Instagram-node-lib project
//              almost exactly from their subscription class.
//
//
// Examples:
//
//            app.use(PuSHHelper.signature_calculator(config.instagram.client_secret, "/instagram"));
//            app.use(PuSHHelper.signature_calculator(config.flickr.api_secret, "/flickr"));
//
// Returns: nothing directly. Sets req["body-signature"] & req["calculated-signature"] if successful.
exports.PuSHHelper.signature_calculator = function(secret){
  var crypto = require('crypto'),
        http = require('http');

  var saved_secret = secret;
  var route_rule = null;
  var save_body = false;

  var raw_body = null;

  if (arguments.length == 2)
  {
    route_rule = new RegExp(arguments[1]);
  }

  if (arguments.length == 3) {
    save_body = arguments[2];
    if (save_body === true) {
      raw_body = "";
    }
  }

  return function signature_calculator(req, res, next){

    req.setEncoding('utf8');
    // console.log("header: " + req.headers['x-hub-signature'] + " route_rule: " + route_rule + " req.url: " + req.url + " match: " + route_rule.test(req.url));
    if (req.headers['x-hub-signature'] !== undefined && req.headers['x-hub-signature'] !== null) {
      
      // check if route matches
      if (route_rule !== null && !route_rule.test(req.url)) {
        return next();
      }
      
      req.on('data', function(chunk){
          if (req["body-signature"] === undefined || req["body-signature"] === null) {
            req["body-signature"] = crypto.createHmac('sha1', saved_secret);
          }
          req["body-signature"].update(chunk);
          if (save_body === true) {
            req.rawBody = req.rawBody.concat(chunk);
          }
        }).on('end', function(){
          // no op now
        });
    } else {
      // console.log("skipping verifier");
    }
    return next();

  };
};

