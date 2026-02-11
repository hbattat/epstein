const https = require('https');

// EFTA00033115 is a known video in DataSet 8
const START_ID = 33110;
const END_ID = 33120;
const DATASET = 'DataSet 8';
const EXTENSIONS = ['.mp4', '.mov', '.wmv', '.asf', '.avi'];

const sessionCookies = 'justiceGovAgeVerified=true';
const headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Referer': 'https://www.justice.gov/epstein',
    'Cookie': sessionCookies
};

async function checkUrl(url) {
    return new Promise((resolve) => {
        https.get(url, { headers }, (res) => {
            if (res.statusCode === 200) {
                const contentType = res.headers['content-type'] || '';
                resolve({ exists: true, contentType });
            } else {
                resolve({ exists: false });
            }
            res.resume();
        }).on('error', () => resolve({ exists: false }));
    });
}

async function probe() {
    for (let i = START_ID; i <= END_ID; i++) {
        const id = `EFTA000${i}`;
        console.log(`\nProbing ${id}...`);

        for (const ext of EXTENSIONS) {
            const url = `https://www.justice.gov/epstein/files/${encodeURIComponent(DATASET)}/${id}${ext}`;
            const result = await checkUrl(url);
            if (result.exists) {
                console.log(`[FOUND] ${ext} - ${result.contentType}`);
            }
        }

        const pdfUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(DATASET)}/${id}.pdf`;
        const pdfResult = await checkUrl(pdfUrl);
        if (pdfResult.exists) {
            console.log(`[META]  .pdf - ${pdfResult.contentType}`);
        }
    }
}

probe();
