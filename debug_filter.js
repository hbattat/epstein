const jsdom = require("jsdom");
const { JSDOM } = jsdom;
const fs = require('fs');
const path = require('path');

// Mock Data
const mockVideos = [
    { title: "Video 1", tags: ["witness"] },
    { title: "Video 2", tags: ["legal", "jeffrey"] },
    { title: "Video 3", tags: ["witness", "legal"] },
    { title: "Video 4", tags: [] } // No tags
];

// Load app.js content to inject or mock
// Since app.js is DOM-heavy, we will replicate the logic we want to test
// specifically the applyFilters logic regarding Set and AND condition.

const dom = new JSDOM(`<!DOCTYPE html>
<input id="search-input" value="">
<select id="dataset-filter"><option value="all">All</option></select>
<select id="format-filter"><option value="all">All</option></select>
<select id="tag-filter"><option value="all">All</option></select>
<div id="active-tags-container"></div>
<div id="video-grid"></div>
<div id="results-info"></div>
<div id="load-more-container"></div>
<button id="load-more-btn"></button>
`);

global.window = dom.window;
global.document = dom.window.document;
global.HTMLElement = dom.window.HTMLElement;

// Mock variables from app.js scope
let allVideos = mockVideos;
let filteredVideos = [];
let shuffledVideos = []; // Not used in this test
let isRandomized = false;
let selectedTags = new Set();
let searchInput = document.getElementById('search-input');
let datasetFilter = document.getElementById('dataset-filter');
let formatFilter = document.getElementById('format-filter');
let tagFilter = document.getElementById('tag-filter');

// REPLICATE applyFilters Logic from app.js
function applyFilters() {
    console.log('--- Applying Filters ---');
    console.log('Active Tags:', Array.from(selectedTags));

    const query = searchInput.value.trim().toLowerCase();
    const dataset = datasetFilter.value;
    const format = formatFilter.value;

    const sourcePool = allVideos; // Simplified

    filteredVideos = sourcePool.filter(v => {
        // ... (skipping search/dataset/format for this test) ...

        // 4. Multi-Tag Filter (AND Logic)
        if (selectedTags.size > 0) {
            if (!v.tags) return false;
            for (let tag of selectedTags) {
                if (!v.tags.includes(tag)) return false;
            }
        }

        return true;
    });

    console.log(`Filtered Count: ${filteredVideos.length}`);
    filteredVideos.forEach(v => console.log(`- ${v.title} [${v.tags ? v.tags.join(',') : ''}]`));
}

// TEST SCENARIOS
console.log('Test 1: Select #witness');
selectedTags.add('witness');
applyFilters();
// Expect: Video 1, Video 3

console.log('\nTest 2: Select #legal');
selectedTags.add('legal');
applyFilters();
// Expect: Video 3 (witness AND legal)

console.log('\nTest 3: Select #jeffrey');
selectedTags.add('jeffrey');
applyFilters();
// Expect: None (witness AND legal AND jeffrey)

console.log('\nTest 4: Remove #witness');
selectedTags.delete('witness');
applyFilters();
// Expect: Video 2 (legal AND jeffrey) - wait, previous state was witness+legal+jeffrey.
// If we remove witness, we have legal+jeffrey.
// Video 2 has legal, jeffrey. Video 3 has legal, witness.
// So removing witness leaving legal+jeffrey -> Video 2 should show.
