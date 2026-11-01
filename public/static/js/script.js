document.addEventListener('DOMContentLoaded', function () {
    const messageInput = document.getElementById('message-input');
    const charCounter = document.getElementById('char-count');
    const wordCounter = document.getElementById('word-count');
    const btnAnalyze = document.getElementById('btn-analyze');
    const btnClear = document.getElementById('btn-clear');
    const loadingState = document.getElementById('loading-state');
    const resultSection = document.getElementById('result-section');
    const errorAlert = document.getElementById('error-alert');
    const errorMessage = document.getElementById('error-message');

    // Preset samples
    const SAMPLES = {
        spam: "CONGRATULATIONS!! You have won a $1,000 Walmart Gift Card! Claim your instant reward now at http://bit.ly/claim-prize or call 0800-123-4567 before offer expires!",
        ham: "Hi Alex, can you please review the attached project proposal when you have a moment? We can discuss it during tomorrow morning's meeting.",
        phishing: "URGENT SECURITY ALERT: Your bank account has been temporarily restricted. Verify your password and credit card immediately at http://192.168.1.50/verify-account to avoid permanent suspension."
    };

    // Update Counters
    function updateCounters() {
        if (!messageInput) return;
        const text = messageInput.value;
        const charCount = text.length;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        if (charCounter) charCounter.textContent = charCount;
        if (wordCounter) wordCounter.textContent = words;
    }

    if (messageInput) {
        messageInput.addEventListener('input', updateCounters);
    }

    // Preset button handlers
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const sampleType = this.getAttribute('data-sample');
            if (SAMPLES[sampleType] && messageInput) {
                messageInput.value = SAMPLES[sampleType];
                updateCounters();
                hideError();
                hideResult();
            }
        });
    });

    // Clear handler
    if (btnClear) {
        btnClear.addEventListener('click', function () {
            if (messageInput) {
                messageInput.value = '';
                updateCounters();
            }
            hideError();
            hideResult();
        });
    }

    // Form Submit Handler
    const analyzeForm = document.getElementById('analyze-form');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', function (e) {
            e.preventDefault();
            analyzeMessage();
        });
    }

    function hideError() {
        if (errorAlert) errorAlert.classList.add('d-none');
    }

    function showError(msg) {
        if (errorMessage) errorMessage.textContent = msg;
        if (errorAlert) errorAlert.classList.remove('d-none');
    }

    function hideResult() {
        if (resultSection) resultSection.classList.add('d-none');
    }

    function analyzeMessage() {
        const text = messageInput ? messageInput.value.trim() : '';

        if (!text) {
            showError('Please enter or paste a message/email to analyze.');
            return;
        }

        hideError();
        hideResult();

        if (loadingState) loadingState.classList.remove('d-none');
        if (btnAnalyze) btnAnalyze.disabled = true;

        fetch('/api/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: text })
        })
        .then(response => response.json())
        .then(data => {
            if (loadingState) loadingState.classList.add('d-none');
            if (btnAnalyze) btnAnalyze.disabled = false;

            if (data.status === 'success') {
                renderResults(data);
            } else {
                showError(data.message || 'An error occurred during analysis.');
            }
        })
        .catch(err => {
            if (loadingState) loadingState.classList.add('d-none');
            if (btnAnalyze) btnAnalyze.disabled = false;
            showError('Unable to connect to analysis server. Please try again.');
            console.error(err);
        });
    }

    function renderResults(data) {
        const bannerContainer = document.getElementById('banner-container');
        const confidenceVal = document.getElementById('confidence-value');
        const spamProbVal = document.getElementById('spam-prob-val');
        const hamProbVal = document.getElementById('ham-prob-val');
        const spamBar = document.getElementById('spam-progress-bar');
        const hamBar = document.getElementById('ham-progress-bar');
        const indicatorsList = document.getElementById('indicators-list');
        const statsContainer = document.getElementById('stats-grid');

        // Banner
        const isSpam = data.prediction === 'SPAM';
        if (bannerContainer) {
            if (isSpam) {
                bannerContainer.className = 'result-banner-spam';
                bannerContainer.innerHTML = `
                    <div class="banner-title"><i class="fas fa-exclamation-triangle me-2"></i>SPAM / THREAT DETECTED</div>
                    <div class="text-secondary">High probability of unwanted, promotional, scam, or phishing content identified.</div>
                `;
            } else {
                const hasIndicators = data.indicators && data.indicators.length > 0;
                const hamSubtitle = hasIndicators
                    ? 'Classified as safe, but cautionary risk indicators were detected — review the heuristics below.'
                    : 'Clean message body — no significant spam, phishing, or financial risk indicators detected.';
                bannerContainer.className = 'result-banner-ham';
                bannerContainer.innerHTML = `
                    <div class="banner-title"><i class="fas fa-shield-check me-2"></i>MESSAGE APPEARS SAFE (HAM)</div>
                    <div class="text-secondary">${hamSubtitle}</div>
                `;
            }
        }

        // Confidence & Probabilities
        if (confidenceVal) confidenceVal.textContent = `${data.confidence}%`;
        if (spamProbVal) spamProbVal.textContent = `${data.spam_probability}%`;
        if (hamProbVal) hamProbVal.textContent = `${data.ham_probability}%`;

        if (spamBar) spamBar.style.width = `${data.spam_probability}%`;
        if (hamBar) hamBar.style.width = `${data.ham_probability}%`;

        // Indicators
        if (indicatorsList) {
            indicatorsList.innerHTML = '';
            if (data.indicators && data.indicators.length > 0) {
                data.indicators.forEach(ind => {
                    const item = document.createElement('div');
                    item.className = `indicator-item ${ind.severity || 'low'}`;
                    item.innerHTML = `
                        <div class="indicator-title">
                            <i class="fas fa-shield-alt text-${ind.severity === 'high' ? 'danger' : ind.severity === 'medium' ? 'warning' : 'info'} me-2"></i>
                            ${ind.label}
                        </div>
                        <p class="indicator-desc">${ind.description}</p>
                    `;
                    indicatorsList.appendChild(item);
                });
            } else {
                indicatorsList.innerHTML = '<div class="text-center py-4 text-muted small"><i class="fas fa-shield-check text-success me-2"></i>No suspicious heuristic rules were triggered.</div>';
            }
        }

        // Statistics
        if (statsContainer && data.statistics) {
            const st = data.statistics;
            statsContainer.innerHTML = `
                <div class="col-6 col-md-3">
                    <div class="p-3 rounded-3 text-center" style="background:rgba(13, 21, 39, 0.7); border:1px solid var(--card-border);">
                        <i class="fas fa-file-word text-cyan mb-2 fs-5"></i>
                        <div class="text-secondary small fw-semibold">Words</div>
                        <div class="h3 fw-bold text-white mb-0 font-monospace">${st.word_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 rounded-3 text-center" style="background:rgba(13, 21, 39, 0.7); border:1px solid var(--card-border);">
                        <i class="fas fa-font text-cyan mb-2 fs-5"></i>
                        <div class="text-secondary small fw-semibold">Characters</div>
                        <div class="h3 fw-bold text-white mb-0 font-monospace">${st.character_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 rounded-3 text-center" style="background:rgba(13, 21, 39, 0.7); border:1px solid var(--card-border);">
                        <i class="fas fa-link text-cyan mb-2 fs-5"></i>
                        <div class="text-secondary small fw-semibold">URLs Extracted</div>
                        <div class="h3 fw-bold text-white mb-0 font-monospace">${st.url_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-3 rounded-3 text-center" style="background:rgba(13, 21, 39, 0.7); border:1px solid var(--card-border);">
                        <i class="fas fa-radiation text-warning mb-2 fs-5"></i>
                        <div class="text-secondary small fw-semibold">Threat Keywords</div>
                        <div class="h3 fw-bold text-white mb-0 font-monospace">${st.keyword_count}</div>
                    </div>
                </div>
            `;
        }

        if (resultSection) {
            resultSection.classList.remove('d-none');
            resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }
});
