async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    errorEl.classList.add('hidden');
    btn.disabled = true;
    btn.textContent = 'Authenticating...';

    try {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            checkAuth();
        } else {
            errorEl.textContent = data.error || 'Login failed';
            errorEl.classList.remove('hidden');
        }
    } catch (e) {
        errorEl.textContent = 'Network error';
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Log In';
    }
}

async function checkAuth() {
    try {
        const response = await fetch('/api/admin/suggestions');
        if (response.ok) {
            document.getElementById('login-section').classList.add('hidden');
            document.getElementById('dashboard-section').classList.remove('hidden');
            document.getElementById('admin-user-info').classList.remove('hidden');
            loadSuggestions();
        }
    } catch (e) { }
}

async function loadSuggestions() {
    const list = document.getElementById('suggestions-list');
    list.innerHTML = '<div class="text-center py-20 border border-white/5"><p class="text-slate-600 font-mono animate-pulse">Loading suggestions...</p></div>';

    try {
        const response = await fetch('/api/admin/suggestions');
        const suggestions = await response.json();

        if (suggestions.length === 0) {
            list.innerHTML = '<div class="text-center py-20 border border-white/5"><p class="text-slate-600 font-mono italic">No pending suggestions</p></div>';
            return;
        }

        list.innerHTML = '';
        suggestions.forEach(s => {
            const card = document.createElement('div');
            card.className = 'bg-zinc-950 border border-white/5 p-6 flex flex-col md:flex-row justify-between items-center gap-6 hover:border-white/10 transition-all';

            card.innerHTML = `
                <div class="flex-grow space-y-2 w-full">
                    <div class="flex items-center gap-2">
                        <span class="text-xs font-mono text-slate-600 uppercase">Suggested Tag:</span>
                        <input type="text" value="${s.tag}" class="tag-edit-input bg-zinc-900 border border-white/5 px-2 py-1 text-white font-mono text-sm focus:ring-1 focus:ring-green-500 outline-none">
                    </div>
                    <div class="flex flex-col gap-1">
                        <span class="text-xs font-mono text-slate-600 uppercase">Video URL:</span>
                        <a href="${s.videoUrl}" target="_blank" class="text-blue-500 hover:underline font-mono text-[10px] break-all">${s.videoUrl}</a>
                    </div>
                    <div class="flex items-center gap-4 text-[10px] font-mono text-slate-500 uppercase">
                        <span>${new Date(s.timestamp).toLocaleString()}</span>
                        <span>IP: ${s.ip}</span>
                    </div>
                </div>
                <div class="flex gap-3 shrink-0">
                    <button onclick="approveTag(this, '${s.videoUrl}', '${s.timestamp}')" class="px-6 py-2 bg-green-900/20 text-green-500 border border-green-500/50 hover:bg-green-500 hover:text-black transition-all font-bold text-xs uppercase tracking-widest">Approve</button>
                    <button onclick="rejectTag(this, '${s.videoUrl}', '${s.timestamp}')" class="px-6 py-2 border border-white/10 hover:border-red-500 text-slate-500 hover:text-red-500 transition-all font-bold text-xs uppercase tracking-widest">Reject</button>
                </div>
            `;
            list.appendChild(card);
        });
    } catch (e) {
        list.innerHTML = '<p class="text-red-500 font-mono text-center">Failed to load suggestions</p>';
    }
}

async function approveTag(btn, videoUrl, timestamp) {
    const card = btn.closest('.bg-zinc-950');
    const input = card.querySelector('.tag-edit-input');
    const tag = input.value.trim();

    if (!tag) return;

    btn.disabled = true;
    btn.textContent = '...';

    try {
        const response = await fetch('/api/admin/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ videoUrl, tag, timestamp })
        });

        if (response.ok) {
            card.style.opacity = '0.5';
            card.style.pointerEvents = 'none';
            setTimeout(() => card.remove(), 500);
        }
    } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Error';
    }
}

// Reject just removes it from suggestions (same API but we could have a reject specific one, 
// for now let's just use the same logic or implement reject)
// I'll add a simple reject logic to delete it from suggestions without adding to videos.json
async function rejectTag(btn, videoUrl, timestamp) {
    if (!confirm('Reject this suggestion?')) return;

    const card = btn.closest('.bg-zinc-950');
    btn.disabled = true;
    btn.textContent = '...';

    try {
        const response = await fetch('/api/admin/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ videoUrl, timestamp })
        });

        if (response.ok) {
            card.style.opacity = '0.5';
            card.style.pointerEvents = 'none';
            setTimeout(() => card.remove(), 500);
        }
    } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Error';
    }
}

function logout() {
    document.cookie = "sessionToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    location.reload();
}

// Initial check
checkAuth();
