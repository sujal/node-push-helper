var url = require('url')
    , querystring= require('querystring');

function return_http_error(code) {
  var err = new Error(http.STATUS_CODES[code]);
  err.status = code;
  return err;
}

// simple constructor
exports.PuSHHelper = function(){ }

// Public: This method is used to handle the verification request that
//         the pubsubhubbub server sends to the subscribing endpoint.
//
// request    - the request object from the http server request handler
// response   - the response object from the http server request handler
// callback   - callback called when handshake is complete. Signature is 
//              function(err, token)
//              where token is the token passed to the server during the
//              the subscribe request. See the PuSH docs for details.
//              Not every app will use the token.
//
//
//              Note: this code is taken from the Instagram-node-lib project
//              almost exactly from their subscription class.
//
// Examples:
//
//              Here's a sample express.js route that uses this method:
//
//              app.get('/instagram/realtime', function(req, res){
//                PuSHHelper.handshake(req, res, function(err, token){
//                    // do something with token (optional)
//                });
//              });
//
// Returns: Nothing directly. Will call the callback if defined. Otherwise, 
//          it will write and end() the response.
exports.PuSHHelper.handshake(request, response, callback) {
  var body, headers, parsedRequest;
  parsedRequest = url.parse(request.url, true);
  if (parsedRequest['query']['hub.mode'] === 'subscribe' && (parsedRequest['query']['hub.challenge'] != null) && parsedRequest['query']['hub.challenge'].length > 0) {
    body = parsedRequest['query']['hub.challenge'];
    headers = {
      'Content-Length': body.length,
      'Content-Type': 'text/plain'
    };
    response.writeHead(200, headers);
    response.write(body);
    if ((parsedRequest['query']['hub.verify_token'] != null) && (complete != null)) {
      complete(parsedRequest['query']['hub.verify_token']);
    }
  } else {
    response.writeHead(400);
  }
  return response.end();
}

// Public: This method is used when your app handles a PuSH notification
//          from the source server. It validates that the request matches the
//          x-hub-signature sent with the request.
//
//          NOTE: this method requires access to the raw request body, so must
//          be used with the express middleware above or some other code that
//          exposes a rawBody property on the request object.
//
//          Instead of this method, it's better to use the middleware offered below,
//          but if you do want to use this, a simple middleware like this will work:
//
//          app.use (function(req, res, next) {
//            req.rawBody = '';
//            req.setEncoding('utf8');
//            req.on('data', function(chunk) { req.rawBody += chunk });
//            next();
//          });
//
// request - The rest object from the http server request handler
// secret  - The secret is an endpoint specific value used to generate the HMAC digest
//           for Instagram or FB, it's the client secret part of the keys, for example.
//
//              Note: this code is taken from the Instagram-node-lib project
//              almost exactly from their subscription class.
//
// Examples:
//
//          app.post('/instagram/realtime', function(req, res){
//            console.log("Received a notification");
//            if (PuSHHelper.verified(req)) {
//
//              // handle the notification, send response...
//
//            } else {
//
//              // return an error
//
//            }
//          });
//
// Returns: true if the request is valid, false if it is not.
exports.PuSHHelper.verified(request, secret) {
  var calculated_signature, encoding, hmac;
  if (request.rawBody === null || request.headers['x-hub-signature'] === void 0 || request.headers['x-hub-signature'] === null) {
    return false;
  }
  hmac = crypto.createHmac('sha1', secret);
  hmac.update(request.rawBody);
  calculated_signature = hmac.digest(encoding = 'hex');
  if (calculated_signature !== request.headers['x-hub-signature']) {
    return false;
  }
  return true;
}

// Public: This is a middleware that will stream in the request and calculate
//          the HMAC digest on the fly. This should be slightly more
//          memory efficient for most requests. Just drop the middleware in 
//          front of your realtime handling methods. On a bad request, the
//          middleware will return a 204 response in accordance with the spec.
//
//          See the comments inline in the code for details.
//
// secret  - The secret is an endpoint specific value used to generate the HMAC digest
//           for Instagram or FB, it's the client secret part of the keys, for example.
//
//
//              Note: this code is taken from the Instagram-node-lib project
//              almost exactly from their subscription class.
//
//
// Examples:
//
//          app.post('/instagram/realtime', PuSHHelper.verifier(secret), function(req, res){
//
//            // handle the notification, send response...
//
//          });
//
// Returns: nothing directly. Will forward to next middleware if signature passes, or
//          sends a 204 reply with a custom header if it fails.
exports.PuSHHelper.verifier = function(secret){
  var crypto = require('crypto'),
        http = require('http');

  return function verifier(req, res, next){
    if (req.headers['x-hub-signature'] !== undefined && req.headers['x-hub-signature'] !== null) {
      req
        .on('data', function(chunk){
          if (req["body-signature"] != null) {
            req["body-signature"] = crypto.createHmac('sha1', secret);
          } 
          req["body-signature"].update(chunk)
        })
        .on('end', function(){
          if (req["body-signature"] != null) {
            calculated_sig = req["body-signature"].digest(encoding = 'hex');
            if (calculated_sig !== request.headers['x-hub-signature']) {
              // this is the weird thing. We will write and end the response here.
              // but, spec says to return a 2XX. Specifically:
              //
              // "If the signature does not match, subscribers MUST still return 
              // a 2xx success response to acknowledge receipt, but locally ignore
              // the message as invalid."
              
              res.writeHead(204, { 'x-hub-error': "Unable to verify signature" });
              res.end();
              return false;
            } else {
              // we're good to go, call the next middleware.
              next();
            }
          } else {
            // this means our code didn't work... shouldn't get here.
            return next(return_http_error(500));
          }
        });
      
    } else {
      next();
    }
  }
}

