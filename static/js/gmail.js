/**
 * MailVision - Gmail Inbox Scanning & Results Interactive Controller
 */
document.addEventListener('DOMContentLoaded', function () {
    const btnScan = document.getElementById('btn-scan-inbox');
    const btnDisconnect = document.getElementById('btn-disconnect');
    const btnScanNext = document.getElementById('btn-scan-next-batch');
    const loadingState = document.getElementById('scan-loading-state');
    const resultsContainer = document.getElementById('scan-results-container');
    const emailsList = document.getElementById('emails-list');
    const emptyState = document.getElementById('empty-state');
    const emptyStateMessage = document.getElementById('empty-state-message');
    const dynamicAlert = document.getElementById('dynamic-alert');
    const dynamicAlertMessage = document.getElementById('dynamic-alert-message');
    const paginationContainer = document.getElementById('pagination-container');

    const statTotal = document.getElementById('stat-total');
    const statSpam = document.getElementById('stat-spam');
    const statHam = document.getElementById('stat-ham');
    const statHighRisk = document.getElementById('stat-high-risk');

    const filterCountAll = document.getElementById('filter-count-all');
    const filterCountSpam = document.getElementById('filter-count-spam');
    const filterCountHam = document.getElementById('filter-count-ham');
    const filterCountHighRisk = document.getElementById('filter-count-high-risk');
    const filterButtons = document.querySelectorAll('.filter-btn');

    let scannedEmails = [];
    let currentFilter = 'all';
    let nextPageToken = null;

    function showAlert(msg) {
        if (dynamicAlert && dynamicAlertMessage) {
            dynamicAlertMessage.textContent = msg;
            dynamicAlert.classList.remove('d-none');
        }
    }

    function hideAlert() {
        if (dynamicAlert) {
            dynamicAlert.classList.add('d-none');
        }
    }

    function showLoading(show) {
        if (loadingState) {
            if (show) loadingState.classList.remove('d-none');
            else loadingState.classList.add('d-none');
        }
        if (btnScan) btnScan.disabled = show;
        if (btnScanNext) btnScanNext.disabled = show;
    }

    // ------------------------------------------------------------------
    // Disconnect Handler
    // ------------------------------------------------------------------
    if (btnDisconnect) {
        btnDisconnect.addEventListener('click', function () {
            if (!confirm('Are you sure you want to disconnect your Gmail account? Stored authorization tokens will be cleared.')) {
                return;
            }

            btnDisconnect.disabled = true;
            fetch('/gmail/disconnect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = '/gmail';
                } else {
                    showAlert(data.message || 'Failed to disconnect account.');
                    btnDisconnect.disabled = false;
                }
            })
            .catch(err => {
                showAlert('Network error while disconnecting account.');
                btnDisconnect.disabled = false;
            });
        });
    }

    // ------------------------------------------------------------------
    // Scan Inbox Handler
    // ------------------------------------------------------------------
    if (btnScan) {
        btnScan.addEventListener('click', function () {
            hideAlert();
            scannedEmails = [];
            nextPageToken = null;
            if (resultsContainer) resultsContainer.classList.add('d-none');
            if (emptyState) emptyState.classList.add('d-none');

            executeScan(null, false);
        });
    }

    if (btnScanNext) {
        btnScanNext.addEventListener('click', function () {
            if (nextPageToken) {
                executeScan(nextPageToken, true);
            }
        });
    }

    function executeScan(pageToken, append) {
        showLoading(true);
        hideAlert();

        fetch('/api/gmail/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                page_token: pageToken || null,
                max_results: 5
            })
        })
        .then(res => res.json().then(data => ({ status: res.status, body: data })))
        .then(result => {
            showLoading(false);
            const data = result.body;

            if (result.status === 401) {
                showAlert(data.message || 'Gmail authorization expired. Please reconnect your account.');
                setTimeout(() => { window.location.href = '/gmail'; }, 2000);
                return;
            }

            if (data.status !== 'success') {
                showAlert(data.message || 'An error occurred during inbox scanning.');
                return;
            }

            nextPageToken = data.next_page_token || null;

            if (append) {
                scannedEmails = scannedEmails.concat(data.emails || []);
            } else {
                scannedEmails = data.emails || [];
            }

            renderResults(scannedEmails);
        })
        .catch(err => {
            showLoading(false);
            showAlert('Network error communicating with server during scan.');
            console.error(err);
        });
    }

    // ------------------------------------------------------------------
    // Render Results & Filtering
    // ------------------------------------------------------------------
    function renderResults(emails) {
        if (!emails || emails.length === 0) {
            if (emptyState) {
                emptyState.classList.remove('d-none');
                if (emptyStateMessage) emptyStateMessage.textContent = 'No messages were found in your inbox.';
            }
            if (resultsContainer) resultsContainer.classList.add('d-none');
            return;
        }

        if (emptyState) emptyState.classList.add('d-none');
        if (resultsContainer) resultsContainer.classList.remove('d-none');

        const total = emails.length;
        const spamCount = emails.filter(e => e.prediction === 'SPAM').length;
        const hamCount = total - spamCount;
        const highRiskCount = emails.filter(e => (e.risk_level || '').toLowerCase() === 'high').length;

        if (statTotal) statTotal.textContent = total;
        if (statSpam) statSpam.textContent = spamCount;
        if (statHam) statHam.textContent = hamCount;
        if (statHighRisk) statHighRisk.textContent = highRiskCount;

        if (filterCountAll) filterCountAll.textContent = total;
        if (filterCountSpam) filterCountSpam.textContent = spamCount;
        if (filterCountHam) filterCountHam.textContent = hamCount;
        if (filterCountHighRisk) filterCountHighRisk.textContent = highRiskCount;

        if (paginationContainer) {
            if (nextPageToken) {
                paginationContainer.classList.remove('d-none');
            } else {
                paginationContainer.classList.add('d-none');
            }
        }

        renderEmailCards(emails, currentFilter);
    }

    function renderEmailCards(emails, filter) {
        if (!emailsList) return;
        emailsList.innerHTML = '';

        const filtered = emails.filter(email => {
            if (filter === 'spam') return email.prediction === 'SPAM';
            if (filter === 'ham') return email.prediction === 'HAM';
            if (filter === 'high-risk') return (email.risk_level || '').toLowerCase() === 'high';
            return true;
        });

        if (filtered.length === 0) {
            emailsList.innerHTML = `
                <div class="cyber-card text-center py-4">
                    <p class="text-secondary mb-0">No emails match the selected filter (<strong>${filter.toUpperCase()}</strong>).</p>
                </div>
            `;
            return;
        }

        filtered.forEach((email, index) => {
            const isSpam = email.prediction === 'SPAM';
            const riskLevel = email.risk_level || 'Low';
            const card = document.createElement('div');
            card.className = 'cyber-card email-item-card';
            card.style.borderLeft = isSpam ? '3px solid var(--spam-red)' : '3px solid var(--ham-green)';

            const badgeClass = isSpam
                ? 'bg-danger-subtle text-danger border border-danger-subtle'
                : 'bg-success-subtle text-success border border-success-subtle';

            const badgeIcon = isSpam
                ? '<i class="fas fa-exclamation-triangle me-1"></i>SPAM'
                : '<i class="fas fa-check-circle me-1"></i>SAFE (HAM)';

            let riskBadgeClass = 'bg-success-subtle text-success border border-success-subtle';
            let riskIcon = 'fas fa-shield-alt';
            if (riskLevel.toLowerCase() === 'high') {
                riskBadgeClass = 'bg-danger text-white border border-danger shadow-sm';
                riskIcon = 'fas fa-skull-crossbones';
            } else if (riskLevel.toLowerCase() === 'medium') {
                riskBadgeClass = 'bg-warning-subtle text-warning border border-warning-subtle';
                riskIcon = 'fas fa-exclamation-triangle';
            }

            const detailId = `email-detail-${index}`;

            // Build contributing risk reasons HTML
            let reasonsHtml = '';
            const reasonsList = email.risk_reasons || [];
            if (reasonsList.length > 0) {
                reasonsHtml = `
                    <div class="small fw-semibold text-warning mb-1">
                        <i class="fas fa-list-check me-1"></i>Reasons Contributing to Risk Assessment:
                    </div>
                    <ul class="small text-secondary mb-0 ps-3">
                        ${reasonsList.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                    </ul>
                `;
            } else {
                reasonsHtml = `
                    <div class="small text-secondary">
                        <i class="fas fa-info-circle me-1 text-info"></i>No significant threat indicators or scam patterns triggered.
                    </div>
                `;
            }

            // Build indicators HTML
            let indicatorsHtml = '';
            if (email.indicators && email.indicators.length > 0) {
                indicatorsHtml = '<div class="mt-3"><div class="small fw-semibold text-warning mb-2"><i class="fas fa-shield-alt me-1"></i>Detected Threat Indicators:</div><div class="d-flex flex-column gap-2">';
                email.indicators.forEach(ind => {
                    const sev = ind.severity || 'low';
                    const iconColor = sev === 'high' ? 'text-danger' : sev === 'medium' ? 'text-warning' : 'text-info';
                    indicatorsHtml += `
                        <div class="indicator-item ${sev} p-2 rounded" style="background:#0d1322; border:1px solid var(--card-border);">
                            <div class="small fw-bold ${iconColor}">
                                <i class="fas fa-circle-exclamation me-1"></i>${escapeHtml(ind.label)}
                            </div>
                            <div class="small text-secondary mt-1">${escapeHtml(ind.description)}</div>
                        </div>
                    `;
                });
                indicatorsHtml += '</div></div>';
            } else {
                indicatorsHtml = '<div class="small text-muted mt-2"><i class="fas fa-check text-success me-1"></i>No suspicious heuristic threat indicators detected.</div>';
            }

            // User feedback state
            const feedbackChoice = email.user_feedback || null;

            card.innerHTML = `
                <div class="cyber-card-body p-3">
                    <div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-2 mb-2">
                        <div class="d-flex align-items-center gap-2 flex-wrap">
                            <span class="badge ${badgeClass} px-2 py-1">${badgeIcon}</span>
                            <span class="badge ${riskBadgeClass} px-2 py-1"><i class="${riskIcon} me-1"></i>${escapeHtml(riskLevel.toUpperCase())} RISK</span>
                            <span class="small font-monospace text-secondary">${escapeHtml(email.sender)}</span>
                            ${email.has_attachments ? '<span class="badge bg-secondary-subtle text-muted small"><i class="fas fa-paperclip me-1"></i>Attachment</span>' : ''}
                        </div>
                        <div class="small text-muted">${escapeHtml(email.date)}</div>
                    </div>

                    <div class="d-flex justify-content-between align-items-center cursor-pointer email-toggle-row" data-target="#${detailId}">
                        <h6 class="text-white mb-1 fw-semibold text-truncate me-2" style="max-width:85%;">
                            ${escapeHtml(email.subject)}
                        </h6>
                        <button type="button" class="btn btn-sm btn-link text-info p-0 text-decoration-none email-expand-btn">
                            <span class="small me-1">Details &amp; Analysis</span><i class="fas fa-chevron-down"></i>
                        </button>
                    </div>

                    <p class="text-secondary small mb-0 text-truncate" style="max-width:95%;">
                        ${escapeHtml(email.snippet || '(No preview snippet available)')}
                    </p>

                    <!-- Expandable Details Section -->
                    <div id="${detailId}" class="email-details-panel d-none mt-3 pt-3 border-top" style="border-color:var(--card-border)!important;">
                        
                        <!-- Security Risk Breakdown Box -->
                        <div class="p-3 mb-3 rounded" style="background:#090d16; border:1px solid var(--card-border);">
                            <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                                <span class="small fw-bold text-white">
                                    <i class="fas fa-shield-halved text-info me-1"></i>Security Assessment vs. ML Prediction
                                </span>
                                <span class="badge ${riskBadgeClass} px-2 py-1">
                                    <i class="${riskIcon} me-1"></i>Risk Level: ${escapeHtml(riskLevel)}
                                </span>
                            </div>
                            <div class="small text-muted mb-2">
                                <strong>ML Prediction:</strong> <span class="${isSpam ? 'text-danger' : 'text-success'} fw-semibold">${email.prediction}</span>
                                <span class="mx-2">&bull;</span>
                                <strong>ML Confidence:</strong> <span class="text-info fw-semibold">${email.confidence}%</span>
                                <span class="small text-secondary ms-2">(Calculated independently from heuristic security risk)</span>
                            </div>
                            ${reasonsHtml}
                        </div>

                        <!-- Probability Distribution Row -->
                        <div class="row g-2 mb-3">
                            <div class="col-md-6">
                                <div class="small text-muted mb-1">Spam Probability: <strong class="text-danger">${email.spam_probability}%</strong></div>
                                <div class="progress" style="height: 6px; background: #0d1322;">
                                    <div class="progress-bar bg-danger" style="width: ${email.spam_probability}%;"></div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="small text-muted mb-1">Ham (Safe) Probability: <strong class="text-success">${email.ham_probability}%</strong></div>
                                <div class="progress" style="height: 6px; background: #0d1322;">
                                    <div class="progress-bar bg-success" style="width: ${email.ham_probability}%;"></div>
                                </div>
                            </div>
                        </div>

                        ${indicatorsHtml}

                        <div class="d-flex gap-3 text-muted small mt-3 pt-2 border-top flex-wrap" style="border-color:var(--card-border)!important;">
                            <span>Words: <strong class="text-white">${email.statistics ? (email.statistics.word_count || 0) : 0}</strong></span>
                            <span>Characters: <strong class="text-white">${email.statistics ? (email.statistics.character_count || 0) : 0}</strong></span>
                            <span>URLs: <strong class="text-white">${email.statistics ? (email.statistics.url_count || 0) : 0}</strong></span>
                            <span>Model Confidence: <strong class="text-info">${email.confidence}%</strong></span>
                        </div>

                        <!-- User Feedback Actions Row -->
                        <div class="feedback-container pt-3 mt-3 border-top d-flex flex-wrap justify-content-between align-items-center gap-2" style="border-color:var(--card-border)!important;">
                            <div class="small text-secondary">
                                <i class="fas fa-comment-dots me-1 text-info"></i>Was MailVision's prediction accurate?
                            </div>
                            <div class="d-flex align-items-center gap-2 feedback-actions" data-email-id="${email.id}">
                                <button type="button" class="btn btn-sm ${feedbackChoice === 'correct' ? 'btn-success' : 'btn-outline-success'} btn-feedback-correct" title="Confirm classification was correct">
                                    <i class="fas fa-thumbs-up me-1"></i>Correct Prediction
                                </button>
                                <button type="button" class="btn btn-sm ${feedbackChoice === 'incorrect' ? 'btn-danger' : 'btn-outline-danger'} btn-feedback-incorrect" title="Report classification was incorrect">
                                    <i class="fas fa-thumbs-down me-1"></i>Incorrect Prediction
                                </button>
                                <span class="feedback-status-badge small ${feedbackChoice ? '' : 'd-none'}">
                                    <span class="badge ${feedbackChoice === 'correct' ? 'bg-success-subtle text-success' : 'bg-warning-subtle text-warning'} border">
                                        <i class="fas fa-check me-1"></i>${feedbackChoice === 'correct' ? 'Marked Correct' : 'Marked Incorrect'}
                                    </span>
                                </span>
                            </div>
                        </div>

                    </div>
                </div>
            `;

            // Add toggle event listener
            const toggleRow = card.querySelector('.email-toggle-row');
            const detailsPanel = card.querySelector(`#${detailId}`);
            const expandBtn = card.querySelector('.email-expand-btn');

            toggleRow.addEventListener('click', function () {
                const isHidden = detailsPanel.classList.contains('d-none');
                if (isHidden) {
                    detailsPanel.classList.remove('d-none');
                    expandBtn.innerHTML = '<span class="small me-1">Collapse</span><i class="fas fa-chevron-up"></i>';
                } else {
                    detailsPanel.classList.add('d-none');
                    expandBtn.innerHTML = '<span class="small me-1">Details &amp; Analysis</span><i class="fas fa-chevron-down"></i>';
                }
            });

            // Feedback button event listeners
            const btnCorrect = card.querySelector('.btn-feedback-correct');
            const btnIncorrect = card.querySelector('.btn-feedback-incorrect');
            const statusBadge = card.querySelector('.feedback-status-badge');

            function submitFeedback(choice) {
                btnCorrect.disabled = true;
                btnIncorrect.disabled = true;

                fetch('/api/gmail/feedback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message_id: email.id,
                        feedback: choice,
                        prediction: email.prediction,
                        confidence: email.confidence,
                        risk_level: email.risk_level
                    })
                })
                .then(res => res.json())
                .then(data => {
                    btnCorrect.disabled = false;
                    btnIncorrect.disabled = false;

                    if (data.status === 'success') {
                        email.user_feedback = choice;
                        if (choice === 'correct') {
                            btnCorrect.className = 'btn btn-sm btn-success btn-feedback-correct';
                            btnIncorrect.className = 'btn btn-sm btn-outline-danger btn-feedback-incorrect';
                            statusBadge.innerHTML = '<span class="badge bg-success-subtle text-success border"><i class="fas fa-check me-1"></i>Marked Correct</span>';
                        } else {
                            btnCorrect.className = 'btn btn-sm btn-outline-success btn-feedback-correct';
                            btnIncorrect.className = 'btn btn-sm btn-danger btn-feedback-incorrect';
                            statusBadge.innerHTML = '<span class="badge bg-warning-subtle text-warning border"><i class="fas fa-check me-1"></i>Marked Incorrect</span>';
                        }
                        statusBadge.classList.remove('d-none');
                    } else {
                        alert(data.message || 'Failed to submit feedback.');
                    }
                })
                .catch(err => {
                    btnCorrect.disabled = false;
                    btnIncorrect.disabled = false;
                    console.error('Feedback submission error:', err);
                });
            }

            if (btnCorrect) {
                btnCorrect.addEventListener('click', function (e) {
                    e.stopPropagation();
                    submitFeedback('correct');
                });
            }

            if (btnIncorrect) {
                btnIncorrect.addEventListener('click', function (e) {
                    e.stopPropagation();
                    submitFeedback('incorrect');
                });
            }

            emailsList.appendChild(card);
        });
    }

    // Filter Buttons Click
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function () {
            filterButtons.forEach(b => {
                b.classList.remove('active', 'btn-cyber-primary');
                b.classList.add('btn-cyber-outline');
            });
            this.classList.add('active', 'btn-cyber-primary');
            this.classList.remove('btn-cyber-outline');

            currentFilter = this.getAttribute('data-filter');
            renderEmailCards(scannedEmails, currentFilter);
        });
    });

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
});
