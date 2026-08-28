// XIGUASecurity - Main Application Logic
(function () {
    'use strict';

    const app = {
        currentPage: 'home',
        isLoaded: false,
    };

    // ========== DOM References ==========
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ========== Tauri invoke helper ==========
    function invoke(cmd, args) {
        return window.__TAURI__.core.invoke(cmd, args || {});
    }

    // ========== 云端哈希开关状态（统一迁移逻辑，与 bridge.ts 保持一致） ==========
    // 权威 key 为 cloud_hash_enabled_v2（旧版 CloudHashManager）。若 v2 残留为 false
    // 但旧 UI key（cloud_hash_enabled）显示为开/未设置，则迁移为开启，确保 UI 开关与扫描一致。
    function isCloudHashEnabledGlobal() {
        const v2 = localStorage.getItem('cloud_hash_enabled_v2');
        if (v2 !== null) {
            if (v2 === 'true') return true;
            const legacy = localStorage.getItem('cloud_hash_enabled');
            if (legacy !== 'false') {
                localStorage.setItem('cloud_hash_enabled_v2', 'true');
                return true;
            }
            return false;
        }
        const legacy = localStorage.getItem('cloud_hash_enabled');
        const enabled = legacy === null || legacy === 'true';
        localStorage.setItem('cloud_hash_enabled_v2', String(enabled));
        return enabled;
    }

    // ========== Initialization ==========
    document.addEventListener('DOMContentLoaded', () => {
        initLoading();
        initNavigation();
        initWindowControls();
        initSidebarToggle();
        initScanButtons();
        initDriverProtection();
        initHomeProtectionStatus();
        initLogs();
    });

    // ========== Loading Screen ==========
    function initLoading() {
        const overlay = $('#loading_overlay');
        if (overlay) {
            setTimeout(() => {
                overlay.classList.add('fade-out');
                setTimeout(() => {
                    overlay.style.display = 'none';
                    app.isLoaded = true;
                }, 500);
            }, 800);
        }
    }

    // ========== Navigation ==========
    function initNavigation() {
        const navBtns = $$('.nav-btn[data-page]');
        const pages = $$('.page');

        navBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const pageId = btn.dataset.page;
                navigateTo(pageId);
            });
        });

        // Cards and buttons that navigate to other pages
        const cardNav = $$('.home-scan-btn[data-page]');
        cardNav.forEach(card => {
            card.addEventListener('click', () => {
                const pageId = card.dataset.page;
                navigateTo(pageId);
            });
        });

        function navigateTo(pageId) {
            if (pageId === app.currentPage) return;

            // Update nav buttons
            navBtns.forEach(b => b.classList.remove('active'));
            const activeBtn = document.querySelector(`.nav-btn[data-page="${pageId}"]`);
            if (activeBtn) activeBtn.classList.add('active');

            // Update pages
            pages.forEach(p => p.classList.remove('active'));
            const targetPage = document.getElementById(`page-${pageId}`);
            if (targetPage) targetPage.classList.add('active');

            app.currentPage = pageId;
        }

        // Expose for use by other functions
        app.navigateTo = navigateTo;
    }

    // ========== Window Controls ==========
    function initWindowControls() {
        const { getCurrentWindow } = window.__TAURI__?.window || {};

        const minimizeBtn = $('#minimize_btn');
        const closeBtn = $('#close_btn');

        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', async () => {
                try {
                    const appWindow = getCurrentWindow();
                    await appWindow.minimize();
                } catch (e) {
                    console.log('Window minimize:', e);
                }
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', async () => {
                try {
                    const appWindow = getCurrentWindow();
                    await appWindow.close();
                } catch (e) {
                    console.log('Window close:', e);
                }
            });
        }
    }

    // ========== Sidebar Toggle ==========
    function initSidebarToggle() {
        const toggleBtn = $('#sidebarToggle');
        const sidebar = document.querySelector('.sidebar');

        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener('click', () => {
                sidebar.classList.toggle('expanded');
            });
        }
    }

    // ========== Scan ==========
    function initScanButtons() {
        const modeView = $('#scanModeView');
        const progressView = $('#scanProgressView');
        const resultView = $('#scanResultView');
        const actionCards = $$('.action-card[data-mode]');
        const stopBtn = $('#scanStopBtn');
        const doneBtn = $('#scanDoneBtn');

        if (!modeView || !progressView || !resultView) return;

        const el = {
            title: $('#scanCardTitle'),
            filePath: $('#scanFilePath'),
            progressBar: $('#scanProgressBar'),
            progressFill: $('#scanProgressFill'),
            progressText: $('#scanProgressText'),
            threats: $('#statThreats'),
            scanned: $('#statScanned'),
            total: $('#statTotal'),
            speed: $('#statSpeed'),
            elapsed: $('#statElapsed'),
            threatsArea: $('#scanThreatsArea'),
            threatsEmpty: $('#scanThreatsEmpty'),
            resultSummary: $('#scanResultSummary'),
            resultList: $('#scanResultList'),
            resultEmpty: $('#scanResultEmpty'),
        };

        // 云端哈希库配置（与旧项目一致）
        const CLOUD_URL = 'https://cloudapi.xiguastudio.top';
        const CLOUD_KEY = 'scan_dcc33b100b8a485fb099a5dce4c4f486';
        const CLOUD_ENABLED = true;
        const BATCH = 100;

        const state = {
            running: false,
            files: [],
            index: 0,
            total: 0,
            threats: [],
            startTime: 0,
            lastTs: 0,
            lastCount: 0,
            speedWindow: 0,
        };

        function escapeHtml(s) {
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        function categoryOf(family) {
            const f = (family || '').toLowerCase();
            if (f.includes('ransom')) return 'Ransomware';
            if (f.includes('backdoor') || f.includes('rat')) return 'Backdoor';
            if (f.includes('stealer')) return 'Stealer';
            if (f.includes('miner')) return 'Miner';
            if (f.includes('worm')) return 'Worm';
            if (f.includes('spyware')) return 'Spyware';
            if (f.includes('hacktool')) return 'HackTool';
            if (f.includes('loader')) return 'Loader';
            if (f.includes('trojan')) return 'Trojan';
            if (f.includes('cloud')) return 'Cloud Hash';
            return 'Malware';
        }

        function resetUI() {
            el.title.innerHTML = 'Scanning...';
            el.filePath.textContent = 'Preparing to scan...';
            el.progressFill.style.width = '0%';
            el.progressText.textContent = '0%';
            el.threats.textContent = '0';
            el.scanned.textContent = '0';
            el.total.textContent = '0';
            el.speed.textContent = '0';
            el.elapsed.textContent = '0s';
            el.threatsArea.querySelectorAll('.scan-threat-entry').forEach(n => n.remove());
            el.threatsEmpty.style.display = 'flex';
            el.progressBar.classList.remove('indeterminate', 'danger');
            el.progressFill.classList.remove('danger');
            stopBtn.textContent = 'Stop';
        }

        function setDanger(on) {
            el.progressBar.classList.toggle('danger', on);
            el.progressFill.classList.toggle('danger', on);
        }

        function addThreat(threat) {
            if (state.threats.length >= 30) state.threats.pop();
            state.threats.unshift(threat);
            const entry = document.createElement('div');
            entry.className = 'scan-threat-entry';
            entry.innerHTML = `
                <input type="checkbox" class="threat-checkbox" checked>
                <span class="threat-category-badge">${categoryOf(threat.virus_family)}</span>
                <span class="threat-name">${escapeHtml(threat.virus_family || 'Malware')}</span>
                <span class="threat-path-simple" title="${escapeHtml(threat.file_path)}">${escapeHtml(threat.file_path)}</span>
                <span class="scan-threat-prob">${(threat.probability * 100).toFixed(1)}%</span>`;
            el.threatsArea.prepend(entry);
            el.threatsEmpty.style.display = 'none';
            el.threats.textContent = String(state.threats.length);
            el.title.innerHTML = `Detected <span class="scan-threat-count">${state.threats.length}</span> threats`;
            setDanger(true);
        }

        function updateProgress() {
            const pct = state.total ? Math.floor(state.index / state.total * 100) : 0;
            el.progressFill.style.width = pct + '%';
            el.progressText.textContent = pct + '%';
            el.scanned.textContent = state.index.toLocaleString();
            el.total.textContent = state.total.toLocaleString();
            const sec = Math.floor((Date.now() - state.startTime) / 1000);
            el.elapsed.textContent = sec + 's';

            // 平均速度（云端哈希串行批次，index 跳跃增长，瞬时采样会严重失真飙高）
            const elapsedSec = Math.max(1, (Date.now() - state.startTime) / 1000);
            state.speedWindow = state.index / elapsedSec;
            el.speed.textContent = state.speedWindow > 0.1 ? Math.round(state.speedWindow) + '/s' : '0';

            if (state.index > 0) {
                el.filePath.textContent =
                    state.files[Math.min(state.index - 1, state.files.length - 1)] || '';
            }
        }

        function showResult(stopped) {
            state.running = false;
            const sec = Math.floor((Date.now() - state.startTime) / 1000);
            progressView.classList.add('hidden');
            resultView.classList.remove('hidden');
            if (stopped) {
                el.resultSummary.textContent =
                    `Scan stopped - scanned ${state.index.toLocaleString()} files, found ${state.threats.length} threat(s)`;
            } else {
                el.resultSummary.textContent =
                    `Found ${state.threats.length} threat(s), scanned ${state.index.toLocaleString()} files, took ${sec}s`;
            }
            if (state.threats.length > 0) {
                el.resultEmpty.classList.add('hidden');
                el.resultList.classList.remove('hidden');
                el.resultList.innerHTML = state.threats.map(t => `
                    <div class="scan-simple-item">
                        <input type="checkbox" class="threat-checkbox" checked>
                        <span class="threat-category-badge">${categoryOf(t.virus_family)}</span>
                        <span class="threat-name">${escapeHtml(t.virus_family || 'Malware')}</span>
                        <span class="threat-path-simple" title="${escapeHtml(t.file_path)}">${escapeHtml(t.file_path)}</span>
                    </div>`).join('');
            } else {
                el.resultList.classList.add('hidden');
                el.resultEmpty.classList.remove('hidden');
            }
        }

        async function scanBatchSlice(slice) {
            try {
                // 1. 批量计算哈希
                const hashes = await invoke('calculate_file_hashes_command', { filePaths: slice });
                const hashMap = {};
                slice.forEach((fp, i) => { hashMap[fp] = hashes[i] || null; });

                // 2. 云端哈希批量查询（仅对有哈希的文件）
                const cloudEnabled = isCloudHashEnabledGlobal();
                if (cloudEnabled) {
                    const validHashes = hashes.filter(h => h !== null);
                    if (validHashes.length > 0) {
                        try {
                            const cloudRes = await invoke('cloud_hash_batch_command', {
                                serverUrl: CLOUD_URL,
                                apiKey: CLOUD_KEY,
                                request: { hashes: validHashes },
                            });
                            if (cloudRes && cloudRes.results) {
                                // 建立 hash -> cloud result 映射（统一转小写，避免大小写不一致导致漏匹配）
                                const cloudMap = {};
                                for (const item of cloudRes.results) {
                                    cloudMap[String(item.hash).toLowerCase()] = item;
                                }
                                // 筛选出云端识别为黑/白的文件
                                const knownFiles = [];
                                const unknownFiles = [];
                                const unknownHashes = [];
                                for (const fp of slice) {
                                    const h = hashMap[fp];
                                    if (h && cloudMap[String(h).toLowerCase()]) {
                                        const item = cloudMap[String(h).toLowerCase()];
                                        if (item.result === 'black') {
                                            // 云端黑名单命中：直接标记为威胁
                                            addThreat({
                                                file_path: fp,
                                                file_hash: h,
                                                result: 'MALICIOUS',
                                                virus_family: item.family || 'CloudHash',
                                                probability: 0.95,
                                                threat_name: item.family || 'CloudHash',
                                            });
                                            knownFiles.push(fp);
                                        } else if (item.result === 'white') {
                                            // 云端白名单：直接跳过
                                            knownFiles.push(fp);
                                        } else {
                                            // unknown：需要本地引擎扫描
                                            unknownFiles.push(fp);
                                            unknownHashes.push(h);
                                        }
                                    } else {
                                        unknownFiles.push(fp);
                                        unknownHashes.push(hashMap[fp]);
                                    }
                                }
                                // 3. 本地引擎扫描未知文件（带哈希，可命中本地黑/白名单）
                                if (unknownFiles.length > 0) {
                                    const localRes = await invoke('scan_batch_direct_with_hashes', {
                                        filePaths: unknownFiles,
                                        hashes: unknownHashes,
                                    });
                                    const localResults = JSON.parse(localRes);
                                    for (const r of localResults) {
                                        if (r.result === 'MALICIOUS') addThreat(r);
                                    }
                                }
                            }
                        } catch (e) {
                            console.log('cloud batch error, falling back to local:', e);
                            // 云端查询失败，全部回退到本地引擎
                            const localRes = await invoke('scan_batch_direct_with_hashes', {
                                filePaths: slice,
                                hashes: hashes,
                            });
                            const localResults = JSON.parse(localRes);
                            for (const r of localResults) {
                                if (r.result === 'MALICIOUS') addThreat(r);
                            }
                        }
                    } else {
                        // 没有哈希，直接本地扫描
                        const localRes = await invoke('scan_batch_direct', { filePaths: slice });
                        const localResults = JSON.parse(localRes);
                        for (const r of localResults) {
                            if (r.result === 'MALICIOUS') addThreat(r);
                        }
                    }
                } else {
                    // 云端已禁用，直接本地扫描
                    const localRes = await invoke('scan_batch_direct_with_hashes', {
                        filePaths: slice,
                        hashes: hashes,
                    });
                    const localResults = JSON.parse(localRes);
                    for (const r of localResults) {
                        if (r.result === 'MALICIOUS') addThreat(r);
                    }
                }
            } catch (e) {
                console.log('scan batch error:', e);
            }
            state.index += slice.length;
            updateProgress();
        }

        // 并发多路批次流水线（与旧项目 3 批并行一致）
        async function runScanWorkers() {
            const WORKERS = 3;
            let next = 0;
            const jobs = [];
            for (let w = 0; w < WORKERS; w++) {
                jobs.push((async () => {
                    while (state.running) {
                        const start = next;
                        next += BATCH;
                        if (start >= state.files.length) break;
                        const slice = state.files.slice(start, start + BATCH);
                        await scanBatchSlice(slice);
                    }
                })());
            }
            await Promise.all(jobs);
            if (state.running) {
                showResult(false);
            }
        }

        async function startScan(mode) {
            if (state.running) return;
            resetUI();
            state.running = true;
            state.threats = [];
            state.index = 0;
            state.total = 0;
            state.files = [];
            state.startTime = Date.now();
            state.lastTs = 0;
            state.lastCount = 0;
            state.speedWindow = 0;

            modeView.classList.add('hidden');
            resultView.classList.add('hidden');
            progressView.classList.remove('hidden');
            el.progressBar.classList.add('indeterminate');

            try {
                let files = [];
                if (mode === 'quick') {
                    files = await invoke('get_scan_files');
                } else if (mode === 'full') {
                    files = await invoke('get_full_scan_files');
                } else {
                    const selected = await window.__TAURI__.dialog.open({
                        directory: true,
                        multiple: false,
                        title: 'Select folder to scan',
                    });
                    if (typeof selected !== 'string' || !selected) {
                        cancelScan();
                        return;
                    }
                    files = await invoke('get_scan_files_direct', { paths: [selected] });
                }
                state.files = files || [];
                state.total = state.files.length;
                el.total.textContent = state.total.toLocaleString();
                el.progressBar.classList.remove('indeterminate');
                if (!state.total) {
                    showResult(false);
                    return;
                }
                await runScanWorkers();
            } catch (e) {
                console.log('scan start error:', e);
                cancelScan();
            }
        }

        function cancelScan() {
            state.running = false;
            progressView.classList.add('hidden');
            modeView.classList.remove('hidden');
        }

        function backToMode() {
            state.running = false;
            progressView.classList.add('hidden');
            resultView.classList.add('hidden');
            modeView.classList.remove('hidden');
            resetUI();
        }

        actionCards.forEach(card => {
            card.addEventListener('click', () => startScan(card.dataset.mode));
        });

        stopBtn.addEventListener('click', () => {
            if (state.running) {
                showResult(true);
            } else {
                backToMode();
            }
        });

        doneBtn.addEventListener('click', backToMode);
    }

    // ========== Driver Protection ==========
    function initDriverProtection() {
        const toggle = $('#driverProtectionToggle');
        if (!toggle) return;

        function refresh() {
            invoke('get_driver_protection')
                .then(v => {
                    if (toggle.checked !== !!v) {
                        toggle.checked = !!v;
                    }
                })
                .catch(() => {});
        }

        // 同步当前状态（默认关闭，不自动开启）
        refresh();

        toggle.addEventListener('change', async () => {
            const on = toggle.checked;
            toggle.disabled = true;
            try {
                await invoke('set_driver_protection', { enabled: on });
            } catch (e) {
                console.log('Set driver protection failed:', e);
                toggle.checked = !on;
            }
            toggle.disabled = false;
        });

        // 轮询 Agent 运行状态（进程崩溃/退出时回滚开关）
        setInterval(refresh, 3000);
    }

    // ========== Home Protection Status ==========
    function initHomeProtectionStatus() {
        const img = $('#homeIllustration');
        const title = $('#homeTitle');
        const sub = $('#homeSub');
        const dot = $('#homeStatusDot');
        const text = $('#homeStatusText');
        const suggestion = $('#homeSuggestion');
        const body = $('#suggestionBody');
        const card = $('#suggestionCard');
        const dismissBtn = $('#suggestionDismiss');
        if (!img || !title) return;

        // 忽略状态：仅当前会话有效，刷新或重启后重新显示
        let dismissed = false;

        function getProtectionState() {
            const checks = [
                invoke('get_driver_protection').then(v => ({ key: 'driver', enabled: !!v })),
                invoke('get_script_protection_enabled').then(v => ({ key: 'web', enabled: !!v })),
                invoke('get_network_protection_state').then(s => ({ key: 'network', enabled: s && typeof s.enabled === 'boolean' ? s.enabled : false })),
                invoke('get_endpoint_protection_enabled').then(v => ({ key: 'endpoint', enabled: !!v })),
                Promise.resolve({ key: 'basic', enabled: localStorage.getItem('basic_protection_enabled') !== 'false' }),
                Promise.resolve({ key: 'identity', enabled: localStorage.getItem('protection_identity') !== 'false' }),
                Promise.resolve({ key: 'file', enabled: localStorage.getItem('file_protection_enabled') !== 'false' }),
                Promise.resolve({ key: 'scriptScan', enabled: localStorage.getItem('script_scan_enabled') !== 'false' }),
                Promise.resolve({ key: 'cloudHash', enabled: isCloudHashEnabledGlobal() }),
                Promise.resolve({ key: 'cloudQuery', enabled: localStorage.getItem('cloud_query_enabled') !== 'false' }),
            ];
            return Promise.allSettled(checks).then(results => {
                const states = results.map(r => r.status === 'fulfilled' ? r.value : { key: 'unknown', enabled: false });
                // 驱动防护与端点防护归属同一"内核级防护"组：只需开启其一即达到普通最大防御
                const driver = states.find(s => s.key === 'driver');
                const endpoint = states.find(s => s.key === 'endpoint');
                const kernelOn = (driver && driver.enabled) || (endpoint && endpoint.enabled);
                // 其余独立防护项
                const others = states.filter(s => s.key !== 'driver' && s.key !== 'endpoint');
                const otherDisabled = others.filter(s => !s.enabled);
                const disabled = kernelOn ? otherDisabled : [{ key: 'kernel', enabled: false }, ...otherDisabled];
                return { allOn: kernelOn && otherDisabled.length === 0, disabled };
            });
        }

        function apply(state) {
            const T = (window.XG_I18N && window.XG_I18N.t) ? window.XG_I18N.t : (k) => k;
            if (state.allOn || dismissed) {
                img.src = 'illustration.svg';
                title.textContent = T('home.title');
                sub.textContent = T('home.sub');
                text.innerHTML = T('home.statusOn');
                if (dot) dot.style.background = 'var(--success)';
                if (suggestion) suggestion.style.display = 'none';
            } else {
                img.src = 'illustration-action-needed.svg';
                title.textContent = T('home.actionNeeded');
                sub.textContent = T('home.actionNeededSub');
                text.textContent = T('home.statusOff');
                if (dot) dot.style.background = 'var(--danger)';
                if (suggestion && body) {
                    suggestion.style.display = 'block';
                    body.innerHTML = state.disabled.map(d => {
                        const label = T('home.prot.' + d.key) || d.key;
                        return '<span class="suggestion-tag">' +
                            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
                            label +
                        '</span>';
                    }).join('');
                }
            }
        }

        function refresh() {
            getProtectionState().then(apply).catch(() => apply({ allOn: false, disabled: [] }));
        }

        refresh();
        setInterval(refresh, 3000);

        if (card) {
            card.addEventListener('click', (e) => {
                // 不拦截点击关闭按钮的事件
                if (e.target && typeof e.target.closest === 'function' && e.target.closest('.suggestion-dismiss')) return;
                if (app.navigateTo) app.navigateTo('protection');
            });
        }

        if (dismissBtn) {
            dismissBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                dismissed = true;
                // 立即切换到"设备已受到保护"状态
                const T = (window.XG_I18N && window.XG_I18N.t) ? window.XG_I18N.t : (k) => k;
                img.src = 'illustration.svg';
                title.textContent = T('home.title');
                sub.textContent = T('home.sub');
                text.innerHTML = T('home.statusOn');
                if (dot) dot.style.background = 'var(--success)';
                if (suggestion) suggestion.style.display = 'none';
            });
        }
    }

    // ========== Logs ==========
    function initLogs() {
        const clearBtn = $('#clear_logs_btn');
        const exportBtn = $('#export_logs_btn');
        const logsContainer = $('.logs-container');

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (logsContainer) {
                    logsContainer.innerHTML = `
                        <div class="log-entry">
                            <span class="log-time">--:--:--</span>
                            <span class="log-type log-info">INFO</span>
                            <span class="log-msg">Logs cleared</span>
                        </div>
                    `;
                }
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                alert('Log export functionality will be available in a future update.');
            });
        }
    }

})();
