const https = require('https');

const IDS = [
    { id: 'EFTA02698946', dataset: 'DataSet 11' },
    { id: 'EFTA02674462', dataset: 'DataSet 11' },
    { id: 'EFTA02713876', dataset: 'DataSet 11' }
];

const EXTENSIONS = ['.mp4', '.mov', '.wmv', '.asf', '.avi', '.mpg'];

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
    for (const item of IDS) {
        console.log(`\nProbing ${item.id} in ${item.dataset}...`);
        for (const ext of EXTENSIONS) {
            const url = `https://www.justice.gov/epstein/files/${encodeURIComponent(item.dataset)}/${item.id}${ext}`;
            const result = await checkUrl(url);
            if (result.exists) {
                console.log(`[FOUND] ${ext} - ${result.contentType}`);
            }
        }

        const pdfUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(item.dataset)}/${item.id}.pdf`;
        const pdfResult = await checkUrl(pdfUrl);
        if (pdfResult.exists) {
            console.log(`[META]  .pdf - ${pdfResult.contentType}`);
        }
    }
}

probe();
