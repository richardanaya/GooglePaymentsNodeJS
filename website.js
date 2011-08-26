var express = require('express');
var jwt = require('./jwt');

var SELLER_ID = "INSERT_SELLER_ID_HERE";
var SECRET_KEY = "INSERT_SECRET_KEY_HERE";

var server = express.createServer();

server.configure(
    function() {
        server.use(express.static(__dirname + '/root/'));
    }
);

server.get('/item',
    function(req, res) {
        var item = {
            "iss" : SELLER_ID,
            "aud" : "Google",
            "typ" : "google/payments/inapp/item/v1",
            "exp" : (new Date().getTime() + 60 * 60),
            "iat" : new Date().getTime(),
            "request" : {
                "name" : "Piece  of Cake",
                "description" : "Virtual chocolate cake to fill your virtual tummy",
                "price" : "0.50",
                "currencyCode" : "USD",
                "sellerData" : "user_id:1224245,offer_code:3098576987,affiliate:aksdfbovu9j"
            }
        };

        var itemString = jwt.encode(item,"v0oncVaSVqm3A2_mg396UA");
        res.header('Content-Type', 'text/plain');
        res.send(itemString);
    }
);

server.post('/verifyItem',
    function(req, res) {
        var data = '';
        req.on('data', function(chunk) {
            data += chunk;
        });
        req.on('end', function() {
            console.log(data);
            data = data.substring(4);
            console.log(data);
            var item = jwt.decode(data, SECRET_KEY);
            res.send(item.response.orderId);
	    next();
        });
    }
);


server.get(/^.*$/,
    function(req, res) {
        res.redirect('/index.html');
    }
);

var port = process.env.PORT || 3000;

server.listen(port);
