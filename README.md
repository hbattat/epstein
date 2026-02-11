# Epstein Library Video Vault

A premium web application to browse, search, and view video recordings from the DOJ Epstein Library.

## Features
- **Instant Search**: Local searching of thousands of archive records.
- **Privacy-Focused Proxy**: Bypasses DOJ security blocks for smooth video playback.
- **Premium UI**: Modern dark theme with glassmorphism and smooth animations.

## Setup Instructions

### 1. Build the Video Library (Ultimate Validator)
Since the DOJ website blocks automated scrapers and many archive files are PDFs without videos, this script will attempt to find valid video streams by checking multiple extensions.

1. Open [justice.gov/epstein](https://www.justice.gov/epstein) in Chrome.
2. Clear the age verification prompt.
3. Open **Developer Console** (`F12` or `Cmd+Option+J`).
4. Paste this script and press Enter:

```javascript
(async () => {
    // 1. UI Setup
    const btn = document.createElement('button');
    btn.innerHTML = '📥 Download videos.json (0 results)';
    Object.assign(btn.style, {
        position: 'fixed', top: '20px', right: '20px', zIndex: '10000',
        padding: '15px 25px', backgroundColor: '#005ea2', color: 'white',
        border: 'none', borderRadius: '5px', fontWeight: 'bold', cursor: 'pointer',
        boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
    });
    document.body.appendChild(btn);

    const download = (data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'videos.json'; a.click();
    };

    btn.onclick = () => download(JSON.parse(localStorage.getItem('epstein_scrape') || '[]'));

    // 2. Logic
    const END_PAGE = 380;
    const EXTENSIONS = ['.mp4', '.mov', '.wmv'];
    let current = parseInt(localStorage.getItem('epstein_last_page') || 0);

    if (current >= END_PAGE) {
        if (confirm(`Scrape already reached page ${current}. Would you like to CLEAR and start over?`)) {
            localStorage.removeItem('epstein_scrape');
            localStorage.removeItem('epstein_last_page');
            current = 0;
        } else {
            return; // Stop here if they don't want to start over
        }
    }

    let allVideos = JSON.parse(localStorage.getItem('epstein_scrape') || '[]');

    for (let p = current + 1; p <= END_PAGE; p++) {
        try {
            console.log(`Fetching page ${p}...`);
            const res = await fetch(`https://www.justice.gov/multimedia-search?keys=no%20images%20produced&page=${p}`);
            const json = await res.json();
            const hits = json.hits.hits;
            
            for (const h of hits) {
                const source = h._source;
                const uri = source.ORIGIN_FILE_URI || '';
                const fileName = source.ORIGIN_FILE_NAME || uri.split('/').pop() || 'Unknown';
                const baseName = fileName.replace(/\.[a-z0-9]+$/i, '');
                
                // Extract Dataset (e.g. "DataSet 8") from URI or key
                let dataset = source.DATA_SET;
                if (!dataset && uri) {
                    const match = uri.match(/\/files\/([^/]+)\//);
                    if (match) dataset = match[1];
                }
                if (!dataset) dataset = 'DataSet 8'; 

                const result = {
                    title: source.title || source.LABEL || baseName,
                    dataset: dataset,
                    filename: fileName,
                    playable: false,
                    checked: [],
                    url: null
                };

                // Brute-force check extensions
                for (const ext of EXTENSIONS) {
                    const testUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(dataset)}/${baseName}${ext}`;
                    try {
                        const check = await fetch(testUrl, { method: 'HEAD' });
                        result.checked.push(ext);
                        if (check.ok) {
                            result.playable = true;
                            result.url = testUrl;
                            console.log(`✅ Found: ${testUrl}`);
                            break;
                        }
                    } catch (e) { }
                }

                allVideos.push(result);
            }

            localStorage.setItem('epstein_scrape', JSON.stringify(allVideos));
            localStorage.setItem('epstein_last_page', p);
            btn.innerHTML = `📥 Download videos.json (${allVideos.length} processed)`;
            
            await new Promise(r => setTimeout(r, 800));
        } catch (e) {
            console.error(e);
            alert("Interrupted! Refresh and re-run to resume.");
            return;
        }
    }

    alert("Scrape complete! Page 380 reached.");
    download(allVideos);
})();
```

5. Move the downloaded `videos.json` into this project folder.

### 2. Run the Server
1. Ensure you have Node.js installed.
2. Run `node server.js` in your terminal.
3. Open `http://localhost:3000` in your browser.

## Project Structure
- `index.html`: Main visual interface.
- `app.js`: High-performance search and player logic.
- `style.css`: Premium themes and glassmorphism styles.
- `server.js`: Lightweight Node.js server with video proxy.
- `videos.json`: Your generated library of video records.
