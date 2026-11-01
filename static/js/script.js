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
                    <div class="banner-title"><i class="fas fa-exclamation-triangle me-2"></i>SPAM DETECTED</div>
                    <div>High risk of unwanted, promotional, or phishing content detected.</div>
                `;
            } else {
                const hasIndicators = data.indicators && data.indicators.length > 0;
                const hamSubtitle = hasIndicators
                    ? 'Classified as safe, but risk indicators were detected \u2014 review the details below.'
                    : 'No significant spam or phishing indicators detected.';
                bannerContainer.className = 'result-banner-ham';
                bannerContainer.innerHTML = `
                    <div class="banner-title"><i class="fas fa-check-circle me-2"></i>MESSAGE APPEARS SAFE (HAM)</div>
                    <div>${hamSubtitle}</div>
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
                indicatorsList.innerHTML = '<p class="text-muted small">No suspicious rule-based heuristics triggered.</p>';
            }
        }

        // Statistics
        if (statsContainer && data.statistics) {
            const st = data.statistics;
            statsContainer.innerHTML = `
                <div class="col-6 col-md-3 mb-3">
                    <div class="p-3 border rounded text-center" style="background:#0d1322; border-color:var(--card-border)!important;">
                        <div class="stat-label small">Words</div>
                        <div class="h4 font-weight-bold text-white mb-0">${st.word_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="p-3 border rounded text-center" style="background:#0d1322; border-color:var(--card-border)!important;">
                        <div class="stat-label small">Characters</div>
                        <div class="h4 font-weight-bold text-white mb-0">${st.character_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="p-3 border rounded text-center" style="background:#0d1322; border-color:var(--card-border)!important;">
                        <div class="stat-label small">URLs</div>
                        <div class="h4 font-weight-bold text-white mb-0">${st.url_count}</div>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="p-3 border rounded text-center" style="background:#0d1322; border-color:var(--card-border)!important;">
                        <div class="stat-label small">Suspicious Keywords</div>
                        <div class="h4 font-weight-bold text-white mb-0">${st.keyword_count}</div>
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
