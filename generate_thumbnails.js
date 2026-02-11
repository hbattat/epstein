const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const https = require('https');

const VIDEOS_FILE = path.join(__dirname, 'data', 'videos.json');
const THUMBNAILS_DIR = path.join(__dirname, 'data', 'thumbnails');
const MAPPING_FILE = path.join(__dirname, 'data', 'thumbnails.json');

// Ensure thumbnails directory exists
if (!fs.existsSync(THUMBNAILS_DIR)) {
    fs.mkdirSync(THUMBNAILS_DIR);
}

// Load existing mappings if any
let thumbnailMap = {};
if (fs.existsSync(MAPPING_FILE)) {
    try {
        thumbnailMap = JSON.parse(fs.readFileSync(MAPPING_FILE, 'utf8'));
    } catch (e) {
        console.error('Error reading thumbnails.json:', e.message);
    }
}

async function generateThumbnail(video) {
    const title = video.title || 'untitled';
    const filename = video.filename || 'video';
    const safeTitle = (video.title || video.filename || 'thumb').replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const thumbPath = path.join(THUMBNAILS_DIR, `${safeTitle}.jpg`);
    const relativePath = `data/thumbnails/${safeTitle}.jpg`;

    if (fs.existsSync(thumbPath)) {
        console.log(`Skipping (exists): ${title}`);
        return relativePath;
    }

    let videoUrl = video.url;
    if (!videoUrl) return null;

    if (!videoUrl.startsWith('http')) {
        const dataset = video.dataset || 'DataSet 8';
        videoUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(dataset)}/${videoUrl}`;
    }

    console.log(`Processing: ${title} -> ${videoUrl}`);

    const headers = [
        'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Referer: https://www.justice.gov/epstein',
        'Cookie: justiceGovAgeVerified=true'
    ].join('\r\n');

    return new Promise((resolve, reject) => {
        // FFmpeg command to grab a frame
        // -headers: pass the custom headers for DOJ access
        // -ss 00:00:05: jump to 5 seconds
        // -i: input URL
        // -frames:v 1: output 1 frame
        // -q:v 2: high quality
        // -s 320x180: scaled size
        const ffmpeg = spawn('ffmpeg', [
            '-headers', headers,
            '-ss', '00:00:05',
            '-i', videoUrl,
            '-frames:v', '1',
            '-q:v', '5',
            '-s', '480x270',
            '-f', 'image2',
            '-y',
            thumbPath
        ]);

        ffmpeg.on('close', (code) => {
            if (code === 0) {
                console.log(`Success: ${title}`);
                resolve(relativePath);
            } else {
                console.error(`FFmpeg failed for ${title} (code ${code})`);
                resolve(null);
            }
        });

        ffmpeg.on('error', (err) => {
            console.error(`FFmpeg error for ${title}:`, err.message);
            resolve(null);
        });

        // Timeout after 30 seconds per video
        setTimeout(() => {
            ffmpeg.kill();
            resolve(null);
        }, 30000);
    });
}

async function main() {
    const videos = JSON.parse(fs.readFileSync(VIDEOS_FILE, 'utf8'));
    const playableVideos = videos.filter(v => v.playable || (v.url && v.url.startsWith('http')));

    console.log(`Found ${playableVideos.length} playable videos. Starting generation...`);

    // Process in small batches to not overwhelm the network/system
    const BATCH_SIZE = 5;
    for (let i = 0; i < playableVideos.length; i += BATCH_SIZE) {
        const batch = playableVideos.slice(i, i + BATCH_SIZE);
        const results = await Promise.all(batch.map(v => generateThumbnail(v)));

        // Update map
        batch.forEach((v, index) => {
            if (results[index]) {
                const key = v.url || v.filename;
                thumbnailMap[key] = results[index];
            }
        });

        // Save progress periodically
        fs.writeFileSync(MAPPING_FILE, JSON.stringify(thumbnailMap, null, 2));
        console.log(`Progress: ${i + batch.length}/${playableVideos.length}`);
    }

    console.log('Thumbnail generation complete.');
}

main().catch(err => console.error('Main error:', err));
