document.addEventListener('DOMContentLoaded', () => {
    const videoGrid = document.getElementById('video-grid');
    const modal = document.getElementById('video-modal');
    const closeModal = document.querySelector('.close-modal');
    const mainPlayer = document.getElementById('main-player');
    const modalTitle = document.getElementById('modal-title');
    const searchInput = document.getElementById('search-input');
    const datasetFilter = document.getElementById('dataset-filter');
    const formatFilter = document.getElementById('format-filter');
    const resultsInfo = document.getElementById('results-info');
    const loadMoreContainer = document.getElementById('load-more-container');
    const loadMoreBtn = document.getElementById('load-more-btn');
    const modalDownload = document.getElementById('modal-download');
    const randomAuditBtn = document.getElementById('random-audit-btn');

    let searchTimeout;

    // GA4 Event Tracker
    function trackEvent(eventName, eventParams = {}) {
        if (typeof gtag === 'function') {
            gtag('event', eventName, {
                ...eventParams,
                timestamp: new Date().toISOString()
            });
        }
    }

    let allVideos = [];
    let filteredVideos = [];
    let shuffledVideos = [];
    let thumbnailMap = {};
    let displayedCount = 0;
    let isRandomized = false;
    const PAGE_SIZE = 20;

    // Load thumbnail mapping
    // Load static data
    loadVideoData();

    async function loadVideoData() {
        videoGrid.innerHTML = `
            <div class="col-span-full py-20 text-center space-y-4">
                <div class="inline-block animate-spin rounded-none h-12 w-12 border-4 border-green-500/30 border-t-green-500"></div>
                <p class="text-green-500 font-mono tracking-widest uppercase">Initializing Vault Connection...</p>
            </div>
        `;

        try {
            const [thumbResponse, videoResponse] = await Promise.all([
                fetch('data/thumbnails.json').catch(() => ({ ok: false })),
                fetch('data/videos.json')
            ]);

            if (thumbResponse.ok) {
                thumbnailMap = await thumbResponse.json();
            }

            if (!videoResponse.ok) {
                throw new Error('Connection failed. Database potentially offline or not initialized.');
            }

            const data = await videoResponse.json();
            // FILTER: Only show playable videos
            allVideos = data.filter(v => v.playable || (v.url && v.url.startsWith('http')));

            // Populate dataset filter with unique values
            populateFilters();

            filteredVideos = [...allVideos];
            renderInitialResults();
        } catch (error) {
            console.error('Data load error:', error);
            videoGrid.innerHTML = `
                <div class="col-span-full py-20 text-center space-y-6">
                    <div class="text-red-500 font-mono text-xl mb-4">[ERROR: DATA_LOAD_FAILURE]</div>
                    <p class="text-slate-400 max-w-md mx-auto mb-8">
                        The connection to the archive vault failed. This may be due to high congestion or an uninitialized library.
                    </p>
                    <button onclick="location.reload()" class="bg-black hover:bg-green-900/20 text-green-500 font-mono py-3 px-8 border border-green-500 transition-all uppercase tracking-widest">
                        Re-initialize Connection
                    </button>
                    <p class="text-xs text-slate-600 mt-8 font-mono">
                        SYSTEM ADVISORY: If error persists, ensure "node scraper.js" has been executed.
                    </p>
                </div>
            `;
        }
    }

    function populateFilters() {
        // Clear except first option
        while (datasetFilter.options.length > 1) datasetFilter.remove(1);

        const datasets = [...new Set(allVideos.map(v => v.dataset).filter(Boolean))].sort();
        datasets.forEach(ds => {
            const option = document.createElement('option');
            option.value = ds;
            option.textContent = ds;
            datasetFilter.appendChild(option);
        });
    }

    function renderInitialResults() {
        displayedCount = 0;
        videoGrid.innerHTML = '';
        resultsInfo.textContent = `Browsing ${filteredVideos.length.toLocaleString()} recordings`;
        loadMore();
    }

    function loadMore() {
        const nextBatch = filteredVideos.slice(displayedCount, displayedCount + PAGE_SIZE);
        renderVideos(nextBatch, true);
        displayedCount += nextBatch.length;

        if (displayedCount < filteredVideos.length) {
            loadMoreContainer.style.display = 'block';
        } else {
            loadMoreContainer.style.display = 'none';
        }

        if (filteredVideos.length === 0) {
            videoGrid.innerHTML = '<div class="loading"><p>No results found for your search/filters.</p></div>';
        }
    }

    function applyFilters() {
        const query = searchInput.value.trim().toLowerCase();
        const dataset = datasetFilter.value;
        const format = formatFilter.value;

        const sourcePool = isRandomized ? shuffledVideos : allVideos;

        filteredVideos = sourcePool.filter(v => {
            // 1. Search Query
            const matchesQuery = !query ||
                (v.title || '').toLowerCase().includes(query) ||
                (v.dataset || '').toLowerCase().includes(query) ||
                (v.url || '').toLowerCase().includes(query) ||
                (v.filename || '').toLowerCase().includes(query);

            if (!matchesQuery) return false;

            // 2. Dataset Filter
            if (dataset !== 'all' && v.dataset !== dataset) return false;

            // 3. Format Filter (URL extension)
            if (format !== 'all') {
                const url = (v.url || '').toLowerCase();
                if (!url.endsWith(format)) return false;
            }

            return true;
        });

        renderInitialResults();

        // Analytics: Track searches and filters
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            if (query || dataset !== 'all' || format !== 'all') {
                trackEvent('vault_filter', {
                    search_query: query,
                    filter_dataset: dataset,
                    filter_format: format,
                    results_count: filteredVideos.length
                });
            }
        }, 1000);
    }

    // Event Listeners
    datasetFilter.addEventListener('change', applyFilters);
    formatFilter.addEventListener('change', applyFilters);

    searchInput.addEventListener('input', applyFilters);

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            applyFilters();
        }
    });

    loadMoreBtn.addEventListener('click', () => {
        loadMore();
        trackEvent('vault_load_more', {
            new_count: displayedCount,
            total_available: filteredVideos.length
        });
    });

    function toggleRandomize() {
        isRandomized = !isRandomized;

        if (isRandomized) {
            // Fisher-Yates Shuffle
            shuffledVideos = [...allVideos];
            for (let i = shuffledVideos.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [shuffledVideos[i], shuffledVideos[j]] = [shuffledVideos[j], shuffledVideos[i]];
            }
            randomAuditBtn.classList.add('bg-green-600', 'text-black');
            randomAuditBtn.classList.remove('bg-black', 'text-green-500');
            randomAuditBtn.textContent = 'RESTORE';
        } else {
            randomAuditBtn.classList.remove('bg-green-600', 'text-black');
            randomAuditBtn.classList.add('bg-black', 'text-green-500');
            randomAuditBtn.textContent = 'Randomize';
        }

        applyFilters();

        trackEvent('vault_randomize_toggle', {
            state: isRandomized ? 'on' : 'off',
            total_videos: allVideos.length
        });
    }

    if (randomAuditBtn) {
        randomAuditBtn.addEventListener('click', toggleRandomize);
    }

    function renderVideos(videos, append = false) {
        if (!append) videoGrid.innerHTML = '';

        videos.forEach(video => {
            const card = document.createElement('div');
            const isPlayable = video.playable || (video.url && video.url.startsWith('http'));

            // Premium Card Wrapper
            card.className = `group relative bg-black border border-green-900 rounded-none overflow-hidden transition-all duration-500 hover:z-10 hover:shadow-2xl hover:shadow-green-500/20 hover:-translate-y-2 cursor-pointer`;

            const format = video.url ? video.url.split('.').pop().toUpperCase() : 'MP4';
            const statusHtml = `<span class="px-3 py-1 bg-green-500/20 text-green-400 border border-green-500/30 rounded-none text-[10px] font-bold uppercase tracking-wider">${format}</span>`;

            // Prepare download link using proxy
            let downloadUrl = video.url;
            if (downloadUrl && !downloadUrl.startsWith('http')) {
                const dataset = video.dataset || 'DataSet 8';
                downloadUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(dataset)}/${downloadUrl}`;
            }
            const proxyDownloadUrl = downloadUrl ? `/proxy?url=${encodeURIComponent(downloadUrl)}` : '#';
            const actualFilename = downloadUrl ? downloadUrl.split('/').pop() : (video.filename || 'video');

            const thumbUrl = thumbnailMap[video.url] || thumbnailMap[video.filename];

            card.innerHTML = `
                <div class="aspect-video relative overflow-hidden bg-black flex items-center justify-center">
                    <!-- Thumbnail Background -->
                    ${thumbUrl
                    ? `<img src="${thumbUrl}" class="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-110 opacity-60" loading="lazy" />`
                    : `<div class="absolute inset-0 bg-black transition-transform duration-700 group-hover:scale-110"></div>`
                }
                    
                    <div class="w-14 h-14 bg-green-600 rounded-none flex items-center justify-center relative z-10 shadow-xl shadow-green-600/40 transition-all duration-300 group-hover:scale-125 group-hover:bg-green-500">
                        <svg class="w-6 h-6 text-black translate-x-0.5" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
                    </div>

                    <!-- Top Badge Overlay -->
                    <div class="absolute top-4 left-4 z-20">
                        ${statusHtml}
                    </div>

                    <!-- Download Overlay -->
                    ${downloadUrl ? `
                    <div class="absolute top-4 right-4 z-20 opacity-0 group-hover:opacity-100 transition-all duration-300 translate-y-2 group-hover:translate-y-0">
                        <a href="${proxyDownloadUrl}" download="${actualFilename}" class="flex items-center gap-2 p-2.5 bg-black hover:bg-green-600 text-green-400 hover:text-black rounded-none border border-green-500 transition-all shadow-xl" title="Download Recording" 
                           onclick="event.stopPropagation(); typeof gtag === 'function' && gtag('event', 'vault_video_download', {video_title: '${(video.title || 'Untitled').replace(/'/g, "\\'")}', source: 'card'})">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                        </a>
                    </div>` : ''}
                </div>

                <div class="p-6 space-y-4 bg-black border-t border-green-900">
                    <h3 class="text-green-500 font-mono text-lg leading-snug group-hover:text-green-300 transition-colors line-clamp-2" title="${video.title || 'Untitled'}">
                        [RECORD_ID: ${video.title || 'Untitled'}]
                    </h3>
                    
                    <div class="flex items-center justify-between pt-2">
                        <div class="flex items-center gap-2">
                            <div class="w-6 h-6 rounded-none bg-green-900/20 flex items-center justify-center border border-green-500/30">
                                <span class="text-[10px] font-bold text-green-400">${video.dataset ? video.dataset.split(' ').pop() : 'A'}</span>
                            </div>
                            <span class="text-xs font-mono text-green-700 uppercase tracking-wide">${video.dataset || 'ARCHIVE_DATA'}</span>
                        </div>
                        <span class="text-[10px] font-mono text-green-800 bg-black border border-green-900 px-2 py-1 rounded-none truncate max-w-[100px]">${video.filename || 'N/A'}</span>
                    </div>
                </div>
            `;

            card.addEventListener('click', () => {
                trackEvent('vault_video_click', {
                    video_title: video.title,
                    dataset: video.dataset,
                    filename: video.filename
                });
                openVideo(video);
            });

            videoGrid.appendChild(card);
        });
    }

    function openVideo(video) {
        let finalUrl = video.url;

        if (finalUrl && !finalUrl.startsWith('http')) {
            const dataset = video.dataset || 'DataSet 8';
            finalUrl = `https://www.justice.gov/epstein/files/${encodeURIComponent(dataset)}/${finalUrl}`;
        }

        if (!finalUrl) return;

        trackEvent('vault_video_open', {
            video_title: video.title,
            dataset: video.dataset,
            url: finalUrl
        });

        modalTitle.textContent = video.title || 'Untitled Video';

        const proxyUrl = `/proxy?url=${encodeURIComponent(finalUrl)}`;
        mainPlayer.src = proxyUrl;

        // Setup download button in modal
        if (modalDownload) {
            const filename = finalUrl ? finalUrl.split('/').pop() : (video.filename || 'video');
            modalDownload.href = proxyUrl;
            modalDownload.download = filename;
        }

        // Show modal with animation
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        // Trigger opacity transition
        setTimeout(() => {
            modal.classList.add('opacity-100');
            modal.classList.remove('opacity-0');
        }, 10);

        document.body.style.overflow = 'hidden';
    }

    function closeVideo() {
        modal.classList.add('opacity-0');
        modal.classList.remove('opacity-100');

        // Wait for animation
        setTimeout(() => {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            mainPlayer.pause();
            mainPlayer.src = '';
            document.body.style.overflow = 'auto';
        }, 300);
    }

    closeModal.addEventListener('click', closeVideo);

    modal.addEventListener('click', (e) => {
        // If they click the backdrop (the modal wrapper itself)
        if (e.target === modal) {
            closeVideo();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
            closeVideo();
        }
    });

    // Video Playback Tracking
    mainPlayer.addEventListener('play', () => {
        trackEvent('vault_video_play', {
            video_title: modalTitle.textContent,
            current_time: mainPlayer.currentTime
        });
    });

    // Download Tracking (Modal)
    if (modalDownload) {
        modalDownload.addEventListener('click', () => {
            trackEvent('vault_video_download', {
                video_title: modalTitle.textContent,
                source: 'modal'
            });
        });
    }
});
