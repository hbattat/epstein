const fs = require('fs');
const videos = JSON.parse(fs.readFileSync('data/videos.json', 'utf8'));
const playable = videos.find(v => v.playable && v.url && v.url.startsWith('http'));
if (playable) {
    console.log(JSON.stringify(playable, null, 2));
} else {
    // Fallback if no http url
    const playableFile = videos.find(v => v.playable && v.url);
    if (playableFile) console.log(JSON.stringify(playableFile, null, 2));
    else console.log('No playable video found');
}
