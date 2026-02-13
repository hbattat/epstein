const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const cluster = require('cluster');
const os = require('os');
const zlib = require('zlib');

const PORT = 3000;
// HLS STATE
const hlsOutputDir = path.join(__dirname, 'data', 'hls');

// Ensure HLS dir exists
if (!fs.existsSync(hlsOutputDir)) {
    fs.mkdirSync(hlsOutputDir, { recursive: true });
}

// Cleanup Interval (Every 5 mins)
setInterval(() => {
    const now = Date.now();
    fs.readdir(hlsOutputDir, (err, dirs) => {
        if (err) return;
        dirs.forEach(dir => {
            const dirPath = path.join(hlsOutputDir, dir);
            fs.stat(dirPath, (err, stats) => {
                if (err) return;
                // If directory is older than 30 mins, delete it
                if (now - stats.mtimeMs > 30 * 60 * 1000) {
                    console.log('[HLS] Cleaning up expired session:', dir);
                    fs.rm(dirPath, { recursive: true, force: true }, () => { });
                    // No more long-running processes to kill in VOD mode
                }
            });
        });
    });
}, 5 * 60 * 1000);

const MAX_RATE = 100; // max requests per minute
const numCPUs = 1; // Temporarily disabling clustering to ensure session and cache consistency when HLS files are local

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

const rateLimits = new Map(); // ip -> { count, startTime }

async function probeVideoMetadata(targetUrl) {
    return new Promise((resolve, reject) => {
        const ffprobe = spawn('ffprobe', [
            '-v', 'error',
            '-show_entries', 'format=duration,start_time',
            '-of', 'json',
            '-headers', 'Cookie: justiceGovAgeVerified=true\r\n',
            '-user_agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            targetUrl
        ]);

        let output = '';
        ffprobe.stdout.on('data', data => output += data.toString());
        ffprobe.on('close', code => {
            if (code === 0) {
                try {
                    const data = JSON.parse(output);
                    resolve({
                        duration: parseFloat(data.format.duration),
                        startTime: parseFloat(data.format.start_time || 0)
                    });
                } catch (e) {
                    reject(e);
                }
            }
            else reject(new Error(`ffprobe failed with code ${code}`));
        });
    });
}

function generateVodPlaylist(sessionDir, duration, segmentDuration = 4) {
    const totalSegments = Math.ceil(duration / segmentDuration);
    let playlist = `#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:${segmentDuration}\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n`;

    for (let i = 0; i < totalSegments; i++) {
        const remaining = duration - (i * segmentDuration);
        const currentSegmentDuration = Math.min(segmentDuration, remaining);
        playlist += `#EXTINF:${currentSegmentDuration.toFixed(6)},\nsegment_${i.toString().padStart(3, '0')}.ts\n`;
    }

    playlist += '#EXT-X-ENDLIST\n';
    fs.writeFileSync(path.join(sessionDir, 'master.m3u8'), playlist);
}

const activeTranscodes = new Map(); // segmentPath -> Promise

async function transcodeSegment(targetUrl, index, segmentPath, segmentDuration = 4) {
    if (activeTranscodes.has(segmentPath)) {
        return activeTranscodes.get(segmentPath);
    }

    const transcodePromise = (async () => {
        const sessionDir = path.dirname(segmentPath);
        const metaPath = path.join(sessionDir, 'metadata.json');
        let videoStartTime = 0;
        if (fs.existsSync(metaPath)) {
            try {
                const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
                videoStartTime = meta.startTime || 0;
            } catch (e) { }
        }

        return new Promise((resolve, reject) => {
            const startTime = index * segmentDuration;
            const ffmpegArgs = [
                '-headers', 'Cookie: justiceGovAgeVerified=true\r\n',
                '-user_agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                '-ss', startTime.toString(),
                '-i', targetUrl,
                '-t', segmentDuration.toString(),
                '-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '23',
                '-c:a', 'aac', '-b:a', '128k',
                '-vf', 'setpts=PTS-STARTPTS',
                '-af', 'asetpts=PTS-STARTPTS',
                '-output_ts_offset', startTime.toString(),
                '-muxdelay', '0',
                '-f', 'mpegts',
                segmentPath
            ];

            const ffmpeg = spawn('ffmpeg', ffmpegArgs);
            ffmpeg.stderr.on('data', d => {
                // console.error(`[FFmpeg Segment ${index}] ${d}`);
            });
            ffmpeg.on('close', code => {
                activeTranscodes.delete(segmentPath);
                if (code === 0) resolve();
                else reject(new Error(`ffmpeg failed with code ${code}`));
            });
        });
    })();

    activeTranscodes.set(segmentPath, transcodePromise);
    return transcodePromise;
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

        // Check for download mode
        const mode = parsedUrl.query.mode;

        if (mode === 'download') {
            console.log(`[Proxy] Downloading: ${targetUrl}`);
            const client = targetUrl.startsWith('https') ? https : http;

            // Inject magic headers to bypass age verification
            const options = {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Cookie': 'justiceGovAgeVerified=true'
                }
            };

            client.get(targetUrl, options, (proxyRes) => {
                const headers = {
                    'Content-Type': proxyRes.headers['content-type'],
                    'Content-Length': proxyRes.headers['content-length'],
                    'Content-Disposition': `attachment; filename="${path.basename(new URL(targetUrl).pathname)}"`,
                    'Access-Control-Allow-Origin': '*'
                };
                res.writeHead(proxyRes.statusCode, headers);
                proxyRes.pipe(res);
            }).on('error', (err) => {
                console.error('[Proxy Error]', err);
                res.writeHead(500);
                res.end('Proxy error');
            });
            return;
        }

        // HLS: Return M3U8 Playlist (Default behavior)
        const fileHash = crypto.createHash('md5').update(targetUrl).digest('hex');
        const sessionDir = path.join(hlsOutputDir, fileHash);
        const playlistPath = path.join(sessionDir, 'master.m3u8');

        if (fs.existsSync(playlistPath)) {
            res.writeHead(302, { 'Location': `/stream/${fileHash}/master.m3u8` });
            res.end();
            return;
        }

        if (!fs.existsSync(sessionDir)) {
            fs.mkdirSync(sessionDir, { recursive: true });
        }

        probeVideoMetadata(targetUrl).then(({ duration, startTime }) => {
            // Save metadata for on-demand transcoding
            fs.writeFileSync(path.join(sessionDir, 'metadata.json'), JSON.stringify({ targetUrl, duration, startTime }));

            generateVodPlaylist(sessionDir, duration);
            res.writeHead(302, { 'Location': `/stream/${fileHash}/master.m3u8` });
            res.end();
        }).catch(err => {
            console.error('[HLS Probe Error]', err);
            res.writeHead(500);
            res.end('Failed to probe video duration');
        });
        return;
    }

    // HLS: Serve Segments and Playlist
    if (parsedUrl.pathname.startsWith('/stream/')) {
        const parts = parsedUrl.pathname.split('/');
        // /stream/<hash>/<file>
        const fileHash = parts[2];
        const fileName = parts[3];

        if (!fileHash || !fileName) {
            res.writeHead(400);
            res.end('Invalid stream request');
            return;
        }

        const sessionDir = path.join(hlsOutputDir, fileHash);
        const filePath = path.join(sessionDir, fileName);

        if (fileName === 'master.m3u8') {
            if (fs.existsSync(filePath)) {
                serveFile(res, filePath, 'application/vnd.apple.mpegurl');
            } else {
                res.writeHead(404);
                res.end('Playlist not found');
            }
            return;
        }

        if (fileName.startsWith('segment_') && fileName.endsWith('.ts')) {
            if (fs.existsSync(filePath)) {
                serveFile(res, filePath, 'video/MP2T');
                return;
            }

            // Generate segment on demand
            const match = fileName.match(/segment_(\d+)\.ts/);
            if (!match) {
                res.writeHead(400);
                res.end('Invalid segment name');
                return;
            }
            const segmentIndex = parseInt(match[1]);

            const metaPath = path.join(sessionDir, 'metadata.json');
            if (!fs.existsSync(metaPath)) {
                res.writeHead(404);
                res.end('Session metadata missing');
                return;
            }

            const { targetUrl } = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

            transcodeSegment(targetUrl, segmentIndex, filePath)
                .then(() => {
                    serveFile(res, filePath, 'video/MP2T');
                })
                .catch(err => {
                    console.error('[HLS Transcode Error]', err);
                    if (!res.writableEnded) {
                        res.writeHead(500);
                        res.end('Transcoding failed');
                    }
                });
            return;
        }

        res.writeHead(404);
        res.end('Not found');
        return;
    }

    // Continue to other handlers

    // API: Suggest Tag
    if (pathname === '/api/suggest-tag' && req.method === 'POST') {
        // Logic is below
    } else if (pathname.startsWith('/api') || pathname.startsWith('/proxy') || pathname.startsWith('/stream')) {
        // If it fell through here, it's 404
        if (!res.writableEnded) {
            res.writeHead(404);
            res.end('Not Found');
        }
        return;
    }

    // STATIC FILE SERVER (Fallback)
    // ...

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
        console.log(`Server running on http://localhost:${PORT}`);
        console.log(`Admin Login at http://localhost:${PORT}/admin.html`);
        console.log(`HLS Output Dir: ${hlsOutputDir}`);
    });
}

function serveFile(res, filePath, contentType) {
    fs.stat(filePath, (err, stats) => {
        if (err) {
            res.writeHead(404);
            res.end('File not found');
            return;
        }
        res.writeHead(200, {
            'Content-Type': contentType,
            'Content-Length': stats.size,
            'Access-Control-Allow-Origin': '*'
        });
        fs.createReadStream(filePath).pipe(res);
    });
}
