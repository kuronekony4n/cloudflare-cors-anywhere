const blacklistUrls = [];
const whitelistOrigins = [ ".*" ];

function isListedInWhitelist(uri, listing) {
    let isListed = false;
    if (typeof uri === "string") {
        listing.forEach((pattern) => {
            if (uri.match(pattern) !== null) {
                isListed = true;
            }
        });
    } else {
        isListed = true;
    }
    return isListed;
}

addEventListener("fetch", async event => {
    event.respondWith((async function() {
        const isPreflightRequest = (event.request.method === "OPTIONS");
        const originUrl = new URL(event.request.url);

        function setupCORSHeaders(headers) {
            headers.set("Access-Control-Allow-Origin", event.request.headers.get("Origin"));
            if (isPreflightRequest) {
                headers.set("Access-Control-Allow-Methods", event.request.headers.get("access-control-request-method"));
                const requestedHeaders = event.request.headers.get("access-control-request-headers");
                if (requestedHeaders) {
                    headers.set("Access-Control-Allow-Headers", requestedHeaders);
                }
                headers.delete("X-Content-Type-Options");
            }
            return headers;
        }

        const targetUrl = decodeURIComponent(decodeURIComponent(originUrl.search.substr(1)));
        const originHeader = event.request.headers.get("Origin");
        const connectingIp = event.request.headers.get("CF-Connecting-IP");

        if ((!isListedInWhitelist(targetUrl, blacklistUrls)) && (isListedInWhitelist(originHeader, whitelistOrigins))) {
            let customHeaders = event.request.headers.get("x-cors-headers");
            if (customHeaders !== null) {
                try {
                    customHeaders = JSON.parse(customHeaders);
                } catch (e) {}
            }

            if (originUrl.search.startsWith("?")) {
                const filteredHeaders = {};
                for (const [key, value] of event.request.headers.entries()) {
                    if (
                        (key.match("^origin") === null) &&
                        (key.match("eferer") === null) &&
                        (key.match("^cf-") === null) &&
                        (key.match("^x-forw") === null) &&
                        (key.match("^x-cors-headers") === null)
                    ) {
                        filteredHeaders[key] = value;
                    }
                }

                if (customHeaders !== null) {
                    Object.entries(customHeaders).forEach((entry) => (filteredHeaders[entry[0]] = entry[1]));
                }

                const newRequest = new Request(event.request, {
                    redirect: "follow",
                    headers: filteredHeaders
                });

                const response = await fetch(targetUrl, newRequest);
                let responseHeaders = new Headers(response.headers);
                const exposedHeaders = [];
                const allResponseHeaders = {};
                for (const [key, value] of response.headers.entries()) {
                    exposedHeaders.push(key);
                    allResponseHeaders[key] = value;
                }
                exposedHeaders.push("cors-received-headers");
                responseHeaders = setupCORSHeaders(responseHeaders);

                responseHeaders.set("Access-Control-Expose-Headers", exposedHeaders.join(","));
                responseHeaders.set("cors-received-headers", JSON.stringify(allResponseHeaders));

                const responseBody = isPreflightRequest ? null : await response.arrayBuffer();

                const responseInit = {
                    headers: responseHeaders,
                    status: isPreflightRequest ? 200 : response.status,
                    statusText: isPreflightRequest ? "OK" : response.statusText
                };
                return new Response(responseBody, responseInit);

            } else {
                let responseHeaders = new Headers();
                responseHeaders = setupCORSHeaders(responseHeaders);

                let country = false;
                let colo = false;
                if (typeof event.request.cf !== "undefined") {
                    country = event.request.cf.country || false;
                    colo = event.request.cf.colo || false;
                }

                return new Response(
                    "CLOUDFLARE-CORS-ANYWHERE\n\n" +
                    "Source:\nhttps://github.com/Zibri/cloudflare-cors-anywhere\n\n" +
                    "Usage:\n" +
                    originUrl.origin + "/?uri\n\n" +
                    "Donate:\nhttps://paypal.me/Zibri/5\n\n" +
                    "Limits: 100,000 requests/day\n" +
                    "          1,000 requests/10 minutes\n\n" +
                    (originHeader !== null ? "Origin: " + originHeader + "\n" : "") +
                    "IP: " + connectingIp + "\n" +
                    (country ? "Country: " + country + "\n" : "") +
                    (colo ? "Datacenter: " + colo + "\n" : "") +
                    "\n" +
                    (customHeaders !== null ? "\nx-cors-headers: " + JSON.stringify(customHeaders) : ""),
                    {
                        status: 200
