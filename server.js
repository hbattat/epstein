const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const zlib = require('zlib');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');

const PORT = 3000;
const numCPUs = 1; // Temporarily disabling clustering to ensure session and cache consistency

// RECAPTCHA V3 CONFIGURATION
// Ideally this should be an environment variable
const RECAPTCHA_SECRET_KEY = 'YOUR_SECRET_KEY_HERE'; // User needs to provide this

async function verifyRecaptcha(token, ip) {
    if (!token) return false;

    return new Promise((resolve) => {
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${ip}`;

        https.get(verifyUrl, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    // v3 returns score 0.0 - 1.0
                    // We accept score >= 0.5
                    if (result.success && result.score >= 0.5) {
                        resolve(true);
                    } else {
                        console.warn(`reCAPTCHA failed: success=${result.success}, score=${result.score}`);
                        resolve(false);
                    }
                } catch (e) {
                    console.error('reCAPTCHA parse error:', e);
                    resolve(false);
                }
            });
        }).on('error', (e) => {
            console.error('reCAPTCHA request error:', e);
            resolve(false);
        });
    });
}

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

    const { spawn } = require('child_process');

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

        // Check if transcoding is needed (non-native formats)
        // Native mostly: mp4, webm, ogg, mp3, wav
        // Non-native likely: mov, wmv, avi, mkv, flv, 3gp
        const fileExt = path.extname(new URL(targetUrl).pathname).toLowerCase();
        // We process everything through FFmpeg to ensure fast start (fragmented MP4)
        console.log(`[Stream] Processing ${fileExt}: ${targetUrl}`);

        res.writeHead(200, {
            'Content-Type': 'video/mp4',
            'Access-Control-Allow-Origin': '*',
        });

        // Base args
        let ffmpegArgs = [
            '-i', targetUrl,
            '-movflags', 'frag_keyframe+empty_moov',
            '-f', 'mp4'
        ];

        // Optimization: Remux native MP4s (copy) for speed, Transcode others
        if (fileExt === '.mp4' || fileExt === '.m4a') {
            ffmpegArgs.push('-c', 'copy');
        } else {
            ffmpegArgs.push(
                '-c:v', 'libx264',
                '-preset', 'ultrafast',
                '-c:a', 'aac'
            );
        }

        ffmpegArgs.push('-'); // Output to stdout

        const ffmpeg = spawn('ffmpeg', ffmpegArgs);

        ffmpeg.stdout.pipe(res);

        ffmpeg.stderr.on('data', (data) => {
            // console.log(`FFmpeg Log: ${data}`); // Verbose logging
        });

        ffmpeg.on('close', (code) => {
            if (code !== 0) {
                console.error(`FFmpeg finished with code ${code}`);
            }
            res.end();
        });

        // Clean up if client disconnects
        req.on('close', () => {
            // Silence kill if already closed
            try { ffmpeg.kill(); } catch (e) { }
        });

        return;


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
        req.on('end', async () => {
            try {
                const { videoUrl, tag, captchaToken } = JSON.parse(body);

                // Verify reCAPTCHA
                const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                const isHuman = await verifyRecaptcha(captchaToken, clientIp);

                if (!isHuman) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Anti-spam check failed. Please refresh and try again.' }));
                    return;
                }

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
                // Rate Limiting
                const ip = req.socket.remoteAddress;
                const now = Date.now();
                if (!global.loginAttempts) global.loginAttempts = {};

                // Cleanup old attempts (> 15 mins)
                for (const k in global.loginAttempts) {
                    if (now - global.loginAttempts[k].timestamp > 900000) delete global.loginAttempts[k];
                }

                if (global.loginAttempts[ip] && global.loginAttempts[ip].count >= 5) {
                    const timeLeft = Math.ceil((900000 - (now - global.loginAttempts[ip].timestamp)) / 60000);
                    res.writeHead(429, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Too many failed attempts. Try again in ${timeLeft} minutes.` }));
                    return;
                }

                const { username, password } = JSON.parse(body);
                const usersPath = path.join(__dirname, 'data', 'users.json');
                const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));

                const user = usersData.users.find(u => u.username === username);

                if (user) {
                    const hash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha512').toString('hex');
                    if (hash === user.hash) {
                        // Success - reset attempts
                        if (global.loginAttempts[ip]) delete global.loginAttempts[ip];

                        const sessionToken = Math.random().toString(36).substring(2) + Date.now().toString(36);
                        sessions.set(sessionToken, { username, expires: Date.now() + 3600000 }); // 1 hour
                        res.writeHead(200, {
                            'Set-Cookie': `sessionToken=${sessionToken}; Path=/; HttpOnly; SameSite=Strict`,
                            'Content-Type': 'application/json'
                        });
                        res.end(JSON.stringify({ success: true }));
                        return;
                    }
                }

                // Failure
                if (!global.loginAttempts[ip]) global.loginAttempts[ip] = { count: 1, timestamp: now };
                else global.loginAttempts[ip].count++;

                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid credentials' }));
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

    // Serve index.html for root or /index.html with Dynamic OG Tags
    if (pathname === '/' || pathname === '/index.html') {
        const videoId = parsedUrl.query.v; // Expecting title or ID
        const indexPath = path.join(__dirname, 'index.html');

        fs.readFile(indexPath, 'utf8', (err, html) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading index.html');
                return;
            }

            if (videoId) {
                // Try to find video details
                const videosPath = path.join(__dirname, 'data', 'videos.json');
                const thumbsPath = path.join(__dirname, 'data', 'thumbnails.json');

                try {
                    const videos = JSON.parse(fs.readFileSync(videosPath, 'utf8'));
                    const thumbnails = JSON.parse(fs.readFileSync(thumbsPath, 'utf8'));

                    // Find video by title (which we use as ID mostly) or filename?
                    const video = videos.find(v => v.title === videoId || v.filename === videoId);

                    if (video) {
                        const title = `JEVV - ${video.title || 'Video Recording'}`;
                        const desc = `Watch this recording from the Jeffrey Epstein dataset. ${video.dataset || ''}`;

                        // Resolve thumbnail
                        let thumbUrl = thumbnails[video.url] || thumbnails[video.filename];
                        // If thumb is relative/local, make it absolute for OG
                        if (thumbUrl && !thumbUrl.startsWith('http')) {
                            thumbUrl = `https://jevv.curlybrac.es/${thumbUrl}`;
                        } else if (!thumbUrl) {
                            thumbUrl = 'https://jevv.curlybrac.es/og-preview.png';
                        }

                        // Replace Meta Tags
                        html = html.replace(/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${title}">`);
                        html = html.replace(/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${desc}">`);
                        html = html.replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="${thumbUrl}">`);

                        html = html.replace(/<meta name="twitter:title" content="[^"]*">/, `<meta name="twitter:title" content="${title}">`);
                        html = html.replace(/<meta name="twitter:description" content="[^"]*">/, `<meta name="twitter:description" content="${desc}">`);
                        html = html.replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="${thumbUrl}">`);
                    }
                } catch (e) {
                    // console.error('Error injecting OG data:', e);
                }
            }

            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
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
