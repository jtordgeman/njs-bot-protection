const fs = require('fs');
const crypto = require('crypto');

const noCookiesFileName = '/var/lib/njs/cookies.txt';
const badReputationIPs = loadFile('/var/lib/njs/ips.txt');
const noCookieIPs = loadFile(noCookiesFileName);

let response = '';
const topSecretKey = 'YouWillNeverGuessMe';
const blockedHoursMS = 1 * 1000 * 60 * 60;

function getCookiePayload(name: string, value: string, validHours: number): string {
    const date = new Date();
    date.setTime(date.getTime() + validHours * 1000 * 60 * 60);
    const dateTime = date.getTime();

    const payload = `${value}${dateTime}`;

    // hash the cookie payload
    const hmac = crypto.createHmac('sha256', topSecretKey);
    const cookieValue = hmac.update(payload).digest('hex');

    // return the cookie
    return `${name}=${dateTime}:${cookieValue}; expires=${date.toUTCString()}; path=/`;
}

function loadFile(file: string): string[] {
    let data: string[] = [];
    try {
        data = fs.readFileSync(file).toString().split('\n');
    } catch (e) {
        // unable to read file
    }
    return data;
}

function updateFile(file: string, dataArray: string[]): void {
    try {
        fs.writeFileSync(file, dataArray.join('\n'));
    } catch (e) {
        // unable to write file
    }
}

function verifyIP(r: NginxHTTPRequest): boolean {
    return badReputationIPs.some((ip: string) => ip === r.remoteAddress);
}

function verifyJSCookie(r: NginxHTTPRequest): boolean {
    const cookies = r.headersIn.Cookie;
    const njsCookie =
        cookies &&
        cookies
            .split(';')
            .map((v) => v.split('='))
            .find((x) => x[0] === 'njs');

    try {
        if (!njsCookie || njsCookie.length < 2) {
            // no njs cookie or wrong cookie array length
            const foundIP = noCookieIPs.find((ip: string) => ip.match(r.remoteAddress));
            if (foundIP && Date.now() - parseInt(foundIP.split(':')[1]) <= blockedHoursMS) {
                return false;
            } else {
                const ipIndex = noCookieIPs.findIndex((item: string) => item === foundIP);
                if (ipIndex) {
                    noCookieIPs.splice(ipIndex, 1);
                    updateFile(noCookiesFileName, noCookieIPs);
                }
                return true;
            }
        }
        // njs cookie found, validate it
        const cookieValue = njsCookie && njsCookie[1];
        if (cookieValue) {
            const [cookieTimestamp, cookiePayload] = cookieValue.split(':');
            const requestSignature = `${r.headersIn['User-Agent']}${r.remoteAddress}${cookieTimestamp}`;
            const requestSignatureHmac = crypto.createHmac('sha256', topSecretKey);
            const requestSignatureHex = requestSignatureHmac.update(requestSignature).digest('hex');
            return requestSignatureHex === cookiePayload;
        }

        return false; // if all fails - block the request
    } catch (e) {
        // something went wrong - block the request
        return true; // if all fails - fail open
    }
}

function addSnippet(r: NginxHTTPRequest, data: string | Buffer, flags: NginxHTTPSendBufferOptions) {
    response += data;

    if (flags.last) {
        const signature = `${r.headersIn['User-Agent']}${r.remoteAddress}`;
        const injectedResponse = response.replace(
            /<\/head>/,
            `<script>document.cookie="${getCookiePayload('njs', signature, 1)}"</script></head>`,
        );
        r.sendBuffer(injectedResponse, flags);
    }
}

function verify(r: NginxHTTPRequest): void {
    if (!verifyIP(r) || !verifyJSCookie(r)) {
        r.return(302, '/block.html');
        return;
    }
    r.internalRedirect('@pages');
}

export default { addSnippet, verify };
