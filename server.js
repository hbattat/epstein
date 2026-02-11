const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const zlib = require('zlib');
const cluster = require('cluster');
const os = require('os');

const PORT = 3000;
const numCPUs = 1; // Temporarily disabling clustering to ensure session and cache consistency

// In-memory cache for static assets (up to 50MB total for safety)
const fileCache = new Map();
const MAX_CACHE_SIZE_MB = 50;
let currentCacheSize = 0;

// Simple session management
const sessions = new Map();

function getCookies(req) {
    const list = {};
    const rc = req.headers.cookie;
    rc && rc.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
}

function isAdmin(req) {
    const cookies = getCookies(req);
    return sessions.has(cookies.sessionToken);
}

function serveRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    console.log(`[${new Date().toISOString()}] ${req.method} ${pathname}`);

    // Proxy endpoint to bypass CORS and Referer checks
    if (pathname === '/proxy') {
        const targetUrl = parsedUrl.query.url;
        if (!targetUrl) {
            res.statusCode = 400;
            res.end('Missing url parameter');
            return;
        }

        try {
            new URL(targetUrl);
        } catch (e) {
            console.error(`Invalid URL discarded: ${targetUrl}`);
            res.statusCode = 400;
            res.end('Invalid URL format. Must be a full absolute URL.');
            return;
        }

        const options = {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Referer': 'https://www.justice.gov/epstein',
                'Cookie': 'justiceGovAgeVerified=true'
            }
        };

        https.get(targetUrl, options, (proxyRes) => {
            if (proxyRes.statusCode === 404) {
                res.writeHead(404, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
                res.end('Video not found on source server');
                return;
            }

            const headers = { ...proxyRes.headers };
            headers['Access-Control-Allow-Origin'] = '*';
            headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS';
            headers['Access-Control-Allow-Headers'] = '*';
            delete headers['content-security-policy'];
            delete headers['x-frame-options'];

            res.writeHead(proxyRes.statusCode, headers);
            proxyRes.pipe(res);
        }).on('error', (err) => {
            console.error('Proxy Error:', err.message);
            res.statusCode = 500;
            res.end('Proxy error: ' + err.message);
        });
        return;
    }

    // API: Suggest Tag
    if (pathname === '/api/suggest-tag' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { videoUrl, tag, captchaToken } = JSON.parse(body);

                // VALIDATION
                if (!videoUrl || !tag || !captchaToken) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Missing required fields' }));
                    return;
                }

                const cleanTag = tag.trim();
                if (cleanTag.includes(' ') || cleanTag.length > 20 || cleanTag.length === 0) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid tag. Must be a single word, max 20 characters.' }));
                    return;
                }

                const suggestion = {
                    videoUrl,
                    tag: cleanTag,
                    status: 'pending',
                    timestamp: new Date().toISOString(),
                    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress
                };

                const dataDir = path.join(__dirname, 'data');
                if (!fs.existsSync(dataDir)) {
                    fs.mkdirSync(dataDir);
                }
                const storagePath = path.join(dataDir, 'tag_suggestions.json');

                fs.readFile(storagePath, 'utf8', (err, data) => {
                    let suggestions = [];
                    if (!err && data) {
                        try {
                            suggestions = JSON.parse(data);
                        } catch (e) { suggestions = []; }
                    }

                    suggestions.push(suggestion);

                    fs.writeFile(storagePath, JSON.stringify(suggestions, null, 2), (err) => {
                        if (err) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Failed to save suggestion' }));
                        } else {
                            // Invalidate cache for suggestions.json
                            fileCache.delete(storagePath);
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: true, message: 'Tag suggestion submitted for review' }));
                        }
                    });
                });
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid JSON request' }));
            }
        });
        return;
    }

    // ADMIN LOGIN
    if (pathname === '/api/admin/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const { username, password } = JSON.parse(body);
                const usersPath = path.join(__dirname, 'data', 'users.json');
                const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));

                const user = usersData.users.find(u => u.username === username && u.password === password);

                if (user) {
                    const sessionToken = Math.random().toString(36).substring(2) + Date.now().toString(36);
                    sessions.set(sessionToken, { username, expires: Date.now() + 3600000 }); // 1 hour
                    res.writeHead(200, {
                        'Set-Cookie': `sessionToken=${sessionToken}; Path=/; HttpOnly; SameSite=Strict`,
                        'Content-Type': 'application/json'
                    });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                }
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid request' }));
            }
        });
        return;
    }

    // ADMIN SUGGESTIONS FETCH
    if (pathname === '/api/admin/suggestions' && req.method === 'GET') {
        if (!isAdmin(req)) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        const storagePath = path.join(__dirname, 'data', 'tag_suggestions.json');
        fs.readFile(storagePath, 'utf8', (err, data) => {
            let suggestions = [];
            if (!err && data) {
                try { suggestions = JSON.parse(data); } catch (e) { }
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(suggestions));
        });
        return;
    }

    // ADMIN APPROVE/EDIT TAG
    if (pathname === '/api/admin/approve' && req.method === 'POST') {
        if (!isAdmin(req)) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const { videoUrl, tag, timestamp } = JSON.parse(body);
                const cleanTag = tag.trim();

                // 1. Remove from suggestions
                const suggestionPath = path.join(__dirname, 'data', 'tag_suggestions.json');
                let suggestions = JSON.parse(fs.readFileSync(suggestionPath, 'utf8'));
                suggestions = suggestions.filter(s => !(s.videoUrl === videoUrl && s.timestamp === timestamp));
                fs.writeFileSync(suggestionPath, JSON.stringify(suggestions, null, 2));

                // 2. Add to videos.json
                const videosPath = path.join(__dirname, 'data', 'videos.json');
                const videos = JSON.parse(fs.readFileSync(videosPath, 'utf8'));
                const matches = videos.filter(v => v.url === videoUrl);

                if (matches.length > 0) {
                    matches.forEach(video => {
                        if (!video.tags) video.tags = [];
                        if (!video.tags.includes(cleanTag)) {
                            video.tags.push(cleanTag);
                        }
                    });
                    fs.writeFileSync(videosPath, JSON.stringify(videos, null, 2));
                    // Invalidate cache since videos.json changed
                    fileCache.delete(videosPath);

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Tag approved and added to video' }));
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Video not found' }));
                }
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid request' }));
            }
        });
        return;
    }

    // ADMIN REJECT TAG
    if (pathname === '/api/admin/reject' && req.method === 'POST') {
        if (!isAdmin(req)) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const { videoUrl, timestamp } = JSON.parse(body);
                const suggestionPath = path.join(__dirname, 'data', 'tag_suggestions.json');
                let suggestions = JSON.parse(fs.readFileSync(suggestionPath, 'utf8'));
                suggestions = suggestions.filter(s => !(s.videoUrl === videoUrl && s.timestamp === timestamp));
                fs.writeFileSync(suggestionPath, JSON.stringify(suggestions, null, 2));

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Suggestion rejected and removed' }));
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid request' }));
            }
        });
        return;
    }

    // Static file serving
    let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
    if (!filePath.startsWith(__dirname)) {
        res.statusCode = 403;
        res.end('Forbidden');
        return;
    }

    const extname = path.extname(filePath);
    const mimeTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.mp4': 'video/mp4'
    };
    const contentType = mimeTypes[extname] || 'application/octet-stream';
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const canGzip = acceptEncoding.includes('gzip');

    // Serve from memory cache if available (except for data files)
    /*
    const isDataFile = pathname.startsWith('/data/');
    if (!isDataFile && fileCache.has(filePath)) {
        const { content, gzipContent } = fileCache.get(filePath);
        const headers = {
            'Content-Type': contentType,
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
        };
        if (canGzip && gzipContent) {
            headers['Content-Encoding'] = 'gzip';
            res.writeHead(200, headers);
            res.end(gzipContent);
        } else {
            res.writeHead(200, headers);
            res.end(content);
        }
        return;
    }
    */

    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.statusCode = 404;
                res.end('File not found');
            } else {
                res.statusCode = 500;
                res.end('Server error: ' + error.code);
            }
        } else {
            const isCompressible = contentType.includes('text') || contentType.includes('json') || contentType.includes('javascript');

            if (isCompressible) {
                zlib.gzip(content, (err, compressed) => {
                    const headers = {
                        'Content-Type': contentType,
                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
                    };

                    if (!err && canGzip) {
                        headers['Content-Encoding'] = 'gzip';
                        res.writeHead(200, headers);
                        res.end(compressed);
                    } else {
                        res.writeHead(200, headers);
                        res.end(content);
                    }
                });
            } else {
                res.writeHead(200, {
                    'Content-Type': contentType,
                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
                });
                res.end(content);
            }
        }
    });
}

if (cluster.isMaster) {
    console.log(`Master ${process.pid} is running`);
    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died. Spawning replacement...`);
        cluster.fork();
    });
} else {
    const server = http.createServer(serveRequest);
    server.listen(PORT, () => {
        console.log(`Worker ${process.pid} started on port ${PORT}`);
    });
}
