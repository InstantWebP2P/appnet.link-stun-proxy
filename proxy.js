// Copyright (c) 2013 Tom Zhou<iwebpp@gmail.com>

var WEBPP = require('iwebpp.io'),
    SEP = WEBPP.SEP,
    vURL = WEBPP.vURL,
    URL = require('url'),
    NET = require('net'),
    httpps = require('httpps'),
    url = require('url'),
    httppProxy = require('httpp-proxy'),
    zlib = require('zlib'),
    Buffer = require('buffer').Buffer,
    Iconv = require('iconv-lite'),
    Jschardet = require('jschardet'),
    Connect = require('connect');


// helpers
function isLocalhost(host){
    return ((host === 'localhost') || (host === '127.0.0.1') ||
            (host === '0:0:0:0:0:0:0:1') || (host === '::1'));
}

var vurleregex  = /([0-9]|[a-f]){32}/gi;
var vhostregex  = /([0-9]|[a-f]){32}\.vurl\./gi;
var vpathregex  = /\/vurl\/([0-9]|[a-f]){32}/gi;
var vtokenregex = /\/vtoken\/([0-9]|[a-f]){16}/gi;

// vHost-based web proxy vURL like wxxxp.local.
var vwperegex    = /w([0-9]|[a-f]){32}p/gi;
var vhostwpregex = /w([0-9]|[a-f]){32}p\.local\./gi;

// vPath-based web proxy vURL like /local/wxxxp
var vpathwpregex = /\/local\/w([0-9]|[a-f]){32}p/gi;

// URL regex
var REGEX_URL  = new RegExp('(https?)://[a-z0-9-]+(\.[a-z0-9-]+)+(/?)', 'gi');

// debug level
var debug = 0;

// Proxy class
// a proxy will contain one iwebpp.io name-client
// - options: user custom parameters, like {secmode: ..., usrkey: ..., domain: ..., endpoints: ..., turn: ...}
// - options.secmode: ssl, enable ssl/https; acl, enable ssl/https,host-based ACL
// - options.https: true or false, true for https proxy server, false for http proxy server
// -      fn: callback to pass proxy informations
var Proxy = module.exports = function(options, fn){ 
    var self = this;
       
    if (!(this instanceof Proxy)) return new Proxy(options, fn);
    
    if (typeof options == 'function') {
        fn = options;
        options = {};
    }
    options.https = options.https || true;
        
    // 0.
	// proxy cache
    self.webProxyCache = self.webProxyCache || {};

    // 1.
    // create name client
    var nmcln = self.nmcln = new WEBPP({
        usrinfo: {
            domain: (options && options.domain) || '51dese.com',
            usrkey: (options && options.usrkey) || ('stun-proxy@'+Date.now())
        },
        
        srvinfo: {
            timeout: 20,
            endpoints: (options && options.endpoints) || [
                {ip: 'iwebpp.com', port: 51686},
                {ip: 'iwebpp.com', port: 51868}
            ],
            turn: (options && options.turn) || [
                {ip: 'iwebpp.com', agent: 51866, proxy: 51688}
            ]
        },
        
        // vURL mode: vhost-based
        vmode: vURL.URL_MODE_HOST, 
        
        // secure mode
        secmode: (options && options.secmode === 'ssl') ? SEP.SEP_SEC_SSL : SEP.SEP_SEC_SSL_ACL_HOST
    });
	
	// 2.
	// check ready
	nmcln.on('ready', function(){
	    // http proxy
	    function httpxy(req, res, next) {
		    var vurle, vstrs, urle = req.url;
		    
		    // 1.
		    // match vURL pattern:
		    // - vhost like http(s)://"xxx.vurl."local.iwebpp.com
		    // - vpath like http(s)://local.iwebpp.com"/vurl/xxx"
		    if (vstrs = req.headers.host.match(vhostregex)) {
		        vurle = vstrs[0];
		        if (debug) console.log('proxy for client with vhost:'+vurle);
		    } else if (vstrs = req.url.match(vpathregex)) {
			    vurle = vstrs[0];	       
			    
			    // prune vpath in req.url
	            req.url = req.url.replace(vurle, '');
	            
	            // prune /local/wxxxp path
	            // TBD ... cascade routing
	            req.url = req.url.replace(vpathwpregex, '');
			         
			    if (debug) console.log('proxy for client with vpath:'+vurle);
		    } else {
		        // invalid vURL
	            console.error('invalid URL:'+urle);
	            next();
	            
	            return;
		    }
	
		    if (debug) console.log('Http request proxy for client request.headers:'+JSON.stringify(req.headers)+
		                           ',url:'+urle+',vurl:'+vurle);
		                           
		    // 1.1
	        // !!! rewrite req.url to remove vToken parts
	        // TBD ... vToken check
	        req.url = req.url.replace(vtokenregex, '');         
	        
	        // 1.2
	        // remove local. subdomain
	        // TBD...         
		    
		    // 2.
			// get peer info by vURL
		    nmcln.getvURLInfo(vurle, function(err, routing){
		        // 2.1
		        // check error and authentication 
		        if (err || !routing) {
		            // invalid vURL
	                res.writeHead(400);
	                res.end('invalid URL');
	                console.error('invalid URL:'+urle);
	                
	                // invalide proxy cache
	                if (self.webProxyCache[vurle]) 
	                    self.webProxyCache[vurle] = null;
	                
	                return;
		        } else {
			        // 3.
			        // create proxy instance and cache it
			        if (!self.webProxyCache[vurle]) {
		                // fill routing info and create proxy to peer target
		                var dstip, dstport;
		                
		                if ((nmcln.oipaddr === routing.dst.ipaddr) ||
		                    (isLocalhost(nmcln.oipaddr) && isLocalhost(routing.dst.ipaddr))) {
		                    dstip   = routing.dst.lipaddr;
		                    dstport = routing.dst.lport;
		                } else {
		                    dstip   = routing.dst.ipaddr;
		                    dstport = routing.dst.port;
		                }
		                
			            self.webProxyCache[vurle] = new httppProxy.HttpProxy({
			                       https: options.https || false,
			                changeOrigin: false,
		                          enable: {xforward: true},
			                  
			                target: {
			                    httpp: true,
			                    https: routing.secmode, 
			                    
			                    host: dstip,
			                    port: dstport,
			                    
			                    // set user-specific feature,like maxim bandwidth,etc
			                    localAddress: {
			                        addr: nmcln.ipaddr,
			                        port: nmcln.port, 
			                        
			                        opt: {
			                            mbw: options.mbw || null
			                        }
			                    }
			                }
			            });
			            
					    // 3.1
					    // Handle request error
					    self.webProxyCache[vurle].on('proxyError', function(err, req, res){
					        if (debug) console.error(err+',proxy to '+urle);
					        
					        // send error back
					        try {
					            res.writeHead(500, {'Content-Type': 'text/plain'});
							    if (req.method !== 'HEAD') {
						            if (process.env.NODE_ENV === 'production') {
						                res.write('Internal Server Error');
						            } else {
						                res.write('An error has occurred: ' + JSON.stringify(err));
						            }
						        }
					            res.end();
					        } catch (ex) {
					            console.error("res.end error: %s", ex.message) ;
					        }
					        
		                    // clear vURL entry
		                    self.webProxyCache[vurle] = null;
		                });
		                
		                // 3.2
		                // Handle upgrade error
					    self.webProxyCache[vurle].on('webSocketProxyError', function(err, req, socket, head){
					        if (debug) console.error(err+',proxy to '+urle);
					        
					        // send error back
					        try {
					            if (process.env.NODE_ENV === 'production') {
					                socket.write('Internal Server Error');
					            } else {
					                socket.write('An error has occurred: ' + JSON.stringify(err));
					            }
					            socket.end();
					        } catch (ex) {
					            console.error("socket.end error: %s", ex.message) ;
					        }
					        
					        // clear vURL entry
		                    self.webProxyCache[vurle] = null;
		                });
		                
					    // Handle custom rewrite logics on response for reverse proxy
					    //--> custome rewrite logics ///////////////////////////////////////
					    self.webProxyCache[vurle].on('proxyResponse', function(req, res, response){
					        var prxself = this;
					        if (debug) console.log('Proxy response,'+'req.headers:'+JSON.stringify(req.headers)+
					                               '\n\n,response.statusCode:'+response.statusCode+',response.headers:'+JSON.stringify(response.headers));
					        
					        // 3.3
					        // rewrite href from 2XX text/html response for whole website proxy
					        if ((response.statusCode >= 200 && response.statusCode < 300) && 
					            ('content-type' in response.headers) && 
					            (response.headers['content-type'].match('text/html') ||
					             response.headers['content-type'].match('text/xml'))) {
					            if (debug) console.log('Proxy 200 response,'+'response.headers:'+JSON.stringify(response.headers));
								            
					            // 3.3.0
					            // rewrite Content-Location in response
					            if (response.headers['content-location']) {           
			                        // - rewrite vhref host part by embedded 'wxxxp.local.'
			                        // - rewrite vhref path part by embedded '/local/wxxxp'
			                        response.headers['content-location'] = response.headers['content-location'].replace(REGEX_URL, function(href){
			                            if (href.match(vhostregex) && !(href.match(vhostwpregex))) {
			                                // calculate replaced string
			                                return href.replace(vhostregex, function(vhost){
			                                    var vhoste = vhost.match(vurleregex)[0];
			                                    
			                                    return vhost+'w'+vhoste+'p'+'.local.';
			                                });
			                            } else if (href.match(vpathregex) && !(href.match(vpathwpregex))) {
			                                // append local. subdomain
			                                if (!(/^(https?:\/\/local\.)/gi).test(href)) {
			                                    href = href.replace(/^(https?:\/\/)/gi, href.match(/^(https?:\/\/)/gi)[0]+'local.');
			                                } 
			                                
			                                // calculate replaced string
			                                return href.replace(vpathregex, function(vpath){
			                                    var vpathe = vpath.match(vurleregex)[0];
			                                    
			                                    return vpath+'/local/'+'w'+vpathe+'p';
			                                });
			                            } else {
			                                return href;
			                            }
			                        });
					            }
					            	               
					            // 3.3.1
					            // intercept res.writeHead, res.write and res.end 
					            // notes:
					            // - unzip and zip again
					            // - ...
					            var reshed = {};
					            var resbuf = [];
					            var ressiz = 0;
					            var resstr = '';
					            var _res_write = res.write, _res_end = res.end, _res_writeHead = res.writeHead;
					            var _decomp, _encomp, _codec;
					            
					            // 3.1.1
					            // overwrite res.writeHead by cache statusCode
				                res.writeHead = function(statusCode, reasonPhrase, headers) {
				                    reshed.statusCode = statusCode;
				                    reshed.headers = {};
				                    
				                    if (typeof reasonPhrase === 'object') {
				                        reshed.headers = reasonPhrase;
				                    } else if (typeof headers === 'object') {
				                        reshed.headers = headers;
				                    }
				                    
				                    Object.keys(reshed.headers).forEach(function (key) {
								        res.setHeader(key, reshed.headers[key]);
								    });
				                };
	                
					            // 3.3.2
					            // handle compressed text
					            if (('content-encoding' in response.headers) &&
					                (response.headers['content-encoding'].match('gzip') ||
					                 response.headers['content-encoding'].match('deflate'))) {
					                if (debug) console.log('Proxy ziped response,'+'response.headers:'+JSON.stringify(response.headers));
					                 
					                if (response.headers['content-encoding'].match('gzip')) {
					                    _codec  = 'gzip';
					                    _decomp = zlib.createGunzip();
					                    _encomp = zlib.createGzip();
					                } else {
					                    _codec  = 'deflate';
					                    _decomp = zlib.createInflate();
					                    _encomp = zlib.createDeflate();
					                }
					               	                
					                if (debug) console.log('\n\ngzip');
					                
				                    // 3.3.2.1
				                    // override res.write and res.end
					                res.write = function(trunk){
					                    return _decomp.write(trunk);
					                };
					                res.end = function(trunk){
					                    _decomp.end(trunk);
					                };
					                
				                    // 3.3.3
				                    // in case handle Node.js-not-supported charset
				                    // - detect charset
					                // - decode content by charset 
					                // - rewrite resstr
					                // - send rewrote resstr by charset
					                // - force response on utf-8 charset??? TBD...
					               				                	                    
					                _decomp.on('data', function(text) {
				                        if (text) {
						                    resbuf.push(text);
						                    ressiz += text.length;
						                }
				                    });
				                    _decomp.on('end', function() {		
				                    	// 3.3.3.1
						                // concat big buffer
						                var bigbuf = Buffer.concat(resbuf, ressiz);
						                
						                // 3.3.3.2
						                // detect charset
						                var chardet = Jschardet.detect(bigbuf);
						                var charset = chardet.encoding;
						                
						                if (debug) console.log('charset:'+JSON.stringify(chardet));
						                		                
						                // 3.3.3.3
						                // decode content by charset
						                resstr = Iconv.decode(bigbuf, charset);
						                                
				                        if (debug > 1) console.log('text response:'+resstr);
				                        
				                        // 3.3.3.4
				                        // rewrite text content            
				                        ///console.log('before rewrite:'+JSON.stringify(resstr.match(REGEX_URL)));
				                        									
				                        // 3.3.3.4.1
				                        // - rewrite vhref host part by embedded 'wxxxp.local.'
				                        // - rewrite vhref path part by embedded '/local/wxxxp'
				                        resstr = resstr.replace(REGEX_URL, function(href){
				                            if (href.match(vhostregex) && !(href.match(vhostwpregex))) {
				                                // calculate replaced string
				                                return href.replace(vhostregex, function(vhost){
				                                    var vhoste = vhost.match(vurleregex)[0];
				                                    
				                                    return vhost+'w'+vhoste+'p'+'.local.';
				                                });
				                            } else if (href.match(vpathregex) && !(href.match(vpathwpregex))) {
				                                // append local. subdomain
				                                if (!(/^(https?:\/\/local\.)/gi).test(href)) {
				                                    href = href.replace(/^(https?:\/\/)/gi, href.match(/^(https?:\/\/)/gi)[0]+'local.');
				                                } 
				                                
				                                // calculate replaced string
				                                return href.replace(vpathregex, function(vpath){
				                                    var vpathe = vpath.match(vurleregex)[0];
				                                    
				                                    return vpath+'/local/'+'w'+vpathe+'p';
				                                });
				                            } else {
				                                return href;
				                            }
				                        });
				                        			                        
				                        ///console.log('after rewrite:'+JSON.stringify(resstr.match(REGEX_URL)));
						                if (debug > 1) console.log('overwrote text response:'+resstr);
				                        
				                        // 3.3.3.5
				                        // compress overwrote text and send out
				                        if (_codec === 'gzip') {
				                            var encbuf = Iconv.encode(resstr, charset);
	                            
				                            // rewrite content-length
				                            res.setHeader('content-length', encbuf.length);
				                            res.writeHead = _res_writeHead;
				                            res.writeHead(reshed.statusCode || 200);
				                            
				                            zlib.gzip(encbuf, function(err, buffer) {
				                                if (err) {
				                                    console.log(err+',deflate failed');
				                                    res.emit('error', err+',gzip failed');
				                                } else {
													res.write = _res_write;
													res.end = _res_end;
													
													res.end(buffer);
				                                }
				                            });
				                        } else {
				                            var encbuf = Iconv.encode(resstr, charset);
				                            
				                            // rewrite content-length
				                            res.setHeader('content-length', encbuf.length);
				                            res.writeHead = _res_writeHead;
				                            res.writeHead(reshed.statusCode || 200);
				                            
				                            zlib.deflate(encbuf, function(err, buffer) {
				                                if (!err) {
				                                    console.log(err+',deflate failed');
				                                    res.emit('error', err+',deflate failed');
				                                } else {
													res.write = _res_write;
													res.end = _res_end;
													
													res.end(buffer);
				                                }
				                            });                        
				                        }
				                    });
				                    
				                    // 3.3.4
				                    // decompress data 
				                    _decomp.on('drain', function(){
				                        res.emit('drain');
				                    });
					            } else {
					                if (debug) console.log('\n\nnotzip');
					                
					                // 3.3.5
					                // in case handle Node.js-not-supported charset
				                    // - detect charset
					                // - decode content by charset 
					                // - rewrite resstr
					                // - send rewrote by charset
					                // - force response on utf-8 charset??? TBD...
					                
					                // 3.3.5.1
				                    // override res.write and res.end         
						            res.write = function(text){
						                if (text) {
						                    resbuf.push(text);
						                    ressiz += text.length;
						                }
						                return true;
						            };
						            res.end = function(text){
						                if (text) {
						                    resbuf.push(text);
						                    ressiz += text.length;
						                }
						                
						                // 3.3.5.2
						                // concat big buffer
						                var bigbuf = Buffer.concat(resbuf, ressiz);
						                
						                // 3.3.5.3
						                // detect charset
						                var chardet = Jschardet.detect(bigbuf);
						                var charset = chardet.encoding;
						                
						                if (debug) console.log('charset:'+JSON.stringify(chardet));
						                		                
						                // 3.3.5.4
						                // decode content by charset
						                resstr = Iconv.decode(bigbuf, charset);
						                
						                if (debug > 1) console.log('text response:'+resstr);
						                
				                        // 3.3.5.5
				                        // rewrite text content
				                        ///console.log('before rewrite:'+JSON.stringify(resstr.match(REGEX_URL)));
				                        									
				                        // 3.3.5.5.1
				                        // - rewrite vhref host part by embedded 'wxxxp.local.'
				                        // - rewrite vhref path part by embedded '/local/wxxxp'
				                        resstr = resstr.replace(REGEX_URL, function(href){
				                            if (href.match(vhostregex) && !(href.match(vhostwpregex))) {
				                                // calculate replaced string
				                                return href.replace(vhostregex,  function(vhost){
				                                    var vhoste = vhost.match(vurleregex)[0];
				                                    
				                                    return vhost+'w'+vhoste+'p'+'.local.';
				                                });
				                            } else if (href.match(vpathregex) && !(href.match(vpathwpregex))) {
				                                // append local. subdomain
				                                if (!(/^(https?:\/\/local\.)/gi).test(href)) {
				                                    href = href.replace(/^(https?:\/\/)/gi, href.match(/^(https?:\/\/)/gi)[0]+'local.');
				                                } 
				                                
				                                // calculate replaced string
				                                return href.replace(vpathregex, function(vpath){
				                                    var vpathe = vpath.match(vurleregex)[0];
				                                    
				                                    return vpath+'/local/'+'w'+vpathe+'p';
				                                });
				                            } else {
				                                return href;
				                            }
				                        });
				                        			                        
				                        ///console.log('after rewrite:'+JSON.stringify(resstr.match(REGEX_URL)));
						                if (debug > 1) console.log('overwrote text response:'+resstr);
				                        
				                        // 3.3.6
				                        // send overwrote text out
										res.write = _res_write;
										res.end = _res_end;
										
										var encbuf = Iconv.encode(resstr, charset);
							
							            // rewrite content-length
				                        res.setHeader('content-length', encbuf.length);
				                        res.writeHead = _res_writeHead;
				                        res.writeHead(reshed.statusCode || 200);
				                        
										res.end(encbuf);
						            };
					            }
					        }
					        
					        // 3.4.
					        // ...
					        
					        // 3.5.
					        // rewrite 3XX redirection location by embedded 'wxxxp.local.'			    
						    if ((response.statusCode >= 300 && response.statusCode < 400) &&
						         typeof response.headers.location !== 'undefined') {					          
					            response.headers.location = response.headers.location.replace(REGEX_URL, function(href){
		                            if (href.match(vhostregex) && !(href.match(vhostwpregex))) {
		                                // calculate replaced string
		                                return href.replace(vhostregex, function(vhost){
		                                    var vhoste = vhost.match(vurleregex)[0];
		                                    
		                                    return vhost+'w'+vhoste+'p'+'.local.';
		                                });
		                            } else if (href.match(vpathregex) && !(href.match(vpathwpregex))) {
		                                // append local. subdomain
		                                if (!(/^(https?:\/\/local\.)/gi).test(href)) {
		                                    href = href.replace(/^(https?:\/\/)/gi, href.match(/^(https?:\/\/)/gi)[0]+'local.');
		                                } 
		                                
		                                // calculate replaced string
		                                return href.replace(vpathregex, function(vpath){
		                                    var vpathe = vpath.match(vurleregex)[0];
		                                    
		                                    return vpath+'/local/'+'w'+vpathe+'p';
		                                });
				                    } else {
		                                return href;
		                            }
		                        });
						    }
					    });
					    //<-- custome rewrite logics ///////////////////////////////////////
			        }
			        
			        // 5.
			        // traverse STUN session to peer
			        nmcln.trvsSTUN(vurle, function(err, stun){
			            if (err || !stun) {
				            // STUN not availabe
		                    res.writeHead(400);
		                    res.end('STUN not available, please use TURN');
		                    console.error('STUN not available:'+urle);
			            } else {
			                // 6.
						    // proxy target
					        // work-around first STUN setup hang by redirect 
						    if (stun.firstrun) {
						        res.writeHead(301, {'location': urle});
						        res.end();
					        } else {
					            self.webProxyCache[vurle].proxyRequest(req, res);
					        }
			            }
			        });
		        }
	        });
	    }
	    
	    // create connect App 
	    var appHttp = Connect();
		
	    // hook http proxy
	    appHttp.use(httpxy);
		
	    // hook portal page
	    // TBD...
	    
	    // websocket proxy
	    function wspxy(req, socket, head) {
		    var vurle, vstrs, urle = req.url;
		    
		    // 1.
		    // match vURL pattern:
		    // - vhost like http(s)://"xxx.vurl."local.iwebpp.com
		    // - vpath like http(s)://local.iwebpp.com"/vurl/xxx"
		    if (vstrs = req.headers.host.match(vhostregex)) {
		        vurle = vstrs[0];
		        if (debug) console.log('proxy for client with vhost:'+vurle);
		    } else if (vstrs = req.url.match(vpathregex)) {
			    vurle = vstrs[0];	       
			    
			    // prune vpath in req.url
	            req.url = req.url.replace(vurle, '');
			    
			    // prune /local/wxxxp path
	            // TBD ... cascade routing
	            req.url = req.url.replace(vpathwpregex, '');
	                 
			    if (debug) console.log('proxy for client with vpath:'+vurle);
		    } else {
		        // invalid vURL
	            // MUST not close socket, which will break other upgrade listener
	            console.error('invalid URL:'+urle);
	            return;
		    }
		    
		    if (debug) console.log('Http request proxy for client request.headers:'+JSON.stringify(req.headers)+
		                           ',url:'+urle+',vurl:'+vurle);
		                           
		    // 1.1
	        // !!! rewrite req.url to remove vToken parts
	        // TBD ... vToken check
	        req.url = req.url.replace(vtokenregex, '');                      
		    
		    // 2.
			// get peer info by vURL
		    nmcln.getvURLInfo(vurle, function(err, routing){
		        // 2.1
		        // check error and authentication 
		        if (err || !routing) {
		            // invalid vURL
	                socket.end('invalid URL');
	                console.error('invalid URL:'+urle);
	                
	                // invalide proxy cache
	                if (self.webProxyCache[vurle]) 
	                    self.webProxyCache[vurle] = null;
	                
	                return;
		        } else {
			        // 3.
			        // create proxy instance and cache it
			        if (!self.webProxyCache[vurle]) {
		                // fill routing info and create proxy to peer target
		                var dstip, dstport;
		                
		                if ((nmcln.oipaddr === routing.dst.ipaddr) || 
		                    (isLocalhost(nmcln.oipaddr) && isLocalhost(routing.dst.ipaddr))) {
		                    dstip   = routing.dst.lipaddr;
		                    dstport = routing.dst.lport;
		                } else {
		                    dstip   = routing.dst.ipaddr;
		                    dstport = routing.dst.port;
		                }
		                
			            self.webProxyCache[vurle] = new httppProxy.HttpProxy({
			                       https: options.https || false,
			                changeOrigin: false,
		                          enable: {xforward: true},
			                  
			                target: {
			                    httpp: true,
			                    https: routing.secmode, 
			                    
			                    host: dstip,
			                    port: dstport,
			                    
			                    // set user-specific feature,like maxim bandwidth,etc
			                    localAddress: {
			                        addr: nmcln.ipaddr,
			                        port: nmcln.port, 
			                        
			                        opt: {
			                            mbw: options.mbw || null
			                        }
			                    }
			                }
			            });
			            
					    // Handle request error
					    self.webProxyCache[vurle].on('proxyError', function(err, req, res){
					        if (debug) console.error(err+',proxy to '+urle);
					        
					        // send error back
					        try {
					            res.writeHead(500, {'Content-Type': 'text/plain'});
							    if (req.method !== 'HEAD') {
						            if (process.env.NODE_ENV === 'production') {
						                res.write('Internal Server Error');
						            } else {
						                res.write('An error has occurred: ' + JSON.stringify(err));
						            }
						        }
					            res.end();
					        } catch (ex) {
					            console.error("res.end error: %s", ex.message) ;
					        }
					        
		                    // clear vURL entry
		                    self.webProxyCache[vurle] = null;
		                });
		                
		                // Handle upgrade error
					    self.webProxyCache[vurle].on('webSocketProxyError', function(err, req, socket, head){
					        if (debug) console.error(err+',proxy to '+urle);
					        
					        // send error back
					        try {
					            if (process.env.NODE_ENV === 'production') {
					                socket.write('Internal Server Error');
					            } else {
					                socket.write('An error has occurred: ' + JSON.stringify(err));
					            }
					            socket.end();
					        } catch (ex) {
					            console.error("socket.end error: %s", ex.message) ;
					        }
					        
					        // clear vURL entry
		                    self.webProxyCache[vurle] = null;
		                });
		                
		                // 
			        }
			        		    
			        // 5.
			        // traverse STUN session to peer
			        nmcln.trvsSTUN(vurle, function(err, stun){
			            if (err || !stun) {
				            // STUN not availabe
		                    socket.end('STUN not available, please use TURN');
		                    console.error('STUN not available:'+urle);
			            } else {
			                // 6.
						    // proxy target
					        self.webProxyCache[vurle].proxyWebSocketRequest(req, socket, head);
			            }
			        });		        
		        }
	        });
	    }
    
        // 8.
	    // pass STUN proxy App
	    fn(null, {httpApp: appHttp, wsApp: wspxy});
	});
	
	// 1.2
	// check error
	nmcln.on('error', function(err){
	    console.log('name-client create failed:'+JSON.stringify(err));
	    fn(err);
	});
};

