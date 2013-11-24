// Copyright (c) 2013 Tom Zhou<iwebpp@gmail.com>
var Proxy = require('../proxy');

var prxy = new Proxy(function(err, proxy){
    if (err || !proxy) {
        console.log(err+',create proxy failed');
        return 
    }
    var nmcln = prxy.nmcln;
    
    // start STUN proxy service
    var fs = require('fs');
    var https = require('https');
    var options = {
         key: fs.readFileSync(__dirname+'/../certs/key.pem'),
        cert: fs.readFileSync(__dirname+'/../certs/cert.pem')
    };
    var srv = https.createServer(options);
    
    srv.on('request', proxy.httpApp); 
    srv.on('upgrade', proxy.wsApp);
    
    srv.listen(51688);
    console.log('STUN proxy server listen on port 51688');
    console.log('Usrkey: '+nmcln.usrinfo.usrkey);
});
