# Node PuSH helper

A simple set of functions to handle PubSubHubbub handshakes & verification.

## Details

Many services including RSS aggregators like Google Reader, social networks like Facebook, 
and photo services like Flickr & Instagram implement some variation of 
the [PubSubHubbub protocol](http://code.google.com/p/pubsubhubbub/ "PubSubHubbub Project") (PuSH).

There are two generic bits of functionality that are required when subscribing for PuSH 
updates from these services. First, we need to complete a handshake with the server when 
subscribing.

The second bit is verifying the notification when the server pushes an update. Both of these are
standard, service independent bits of code, so it didn't make sense to use code that's in a particular
library. This library does nothing but those two functions and exposes simple methods
that can be used in an express.js app or anywhere else.

## Examples

Here's my subscription code from my app. 

````javascript
// a GET request will be a challenge query
app.get('/instagram/realtime', function(req, res){
  PuSHHelper.handshake(req, res);
});

// this is where Instagram will send updates (using POST)
app.post('/instagram/realtime', PuSHHelper.verifier(config.instagram.client_secret), function(req, res){
  console.log("Received a notification");
  
  // process the notifications
  
});
````

You can see a working example in the [Proxigram source code](https://github.com/sujal/proxigram). 

## Credits

The library draws functionality from the `instagram-node-lib` NPM located at https://github.com/mckelvey/instagram-node-lib and the `nubnub` project located here: https://github.com/technoweenie/nubnub

----

## License

See the LICENSE file for information
