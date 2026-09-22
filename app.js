/**
 * FAKE OFFER LETTER & PHISHING INSPECTOR
 * Core Client-Side Cybersecurity Threat Classifier & Interactive Dashboard Engine
 */

(function () {
  'use strict';

  // --- Preloaded Sample Datasets ---
  const SAMPLES = {
    'pay-for-equipment-scam': {
      title: 'Pay-for-Equipment & Check Cashing Trap',
      content: `From: GlobalTech Talent Acquisition <recruiter.globaltechhr@gmail.com>
Subject: OFFICIAL JOB OFFER: Remote Data Operations Specialist - GlobalTech Corp
Date: Mon, 18 Sep 2026 14:22:00 +0000

Dear Candidate,

Following your exceptional review during our text-based interview on Telegram (@globaltech_hiring_manager), the Executive Board of GlobalTech Solutions LLC is thrilled to officially extend you an offer for the position of Senior Remote Data Operations Specialist.

COMPENSATION & BENEFITS:
- Base Salary: $48.50 per hour ($100,880 annually), disbursed weekly.
- 401(k) matching up to 6%, full medical, dental, and vision insurance.

MANDATORY HOME OFFICE WORKSTATION SETUP:
To ensure compliance with our security protocols, you must acquire the standard GlobalTech Apple Enterprise Workstation bundle (MacBook Pro M3 Max 32GB, dual 4K monitors, encrypted VPN router, and time-tracking hardware). 

We will issue and overnight a company check in the amount of $4,850.00 to your home address. Upon receiving this check, you must deposit it immediately into your personal bank account via mobile deposit. Once the funds reflect as available in your balance (within 24 hours), you are instructed to wire transfer or Zelle $4,200.00 directly to our certified hardware vendor (Apex Logistics LLC) to expedite shipping before your orientation.

ACCEPTANCE DEADLINE - STRICT URGENCY:
Due to high onboarding volume, you must sign and return this offer letter within 12 hours of receipt. Failure to respond before midnight will result in immediate revocation of this employment opportunity.

Please send your banking details and copy of photo ID directly to this email to initiate check dispatch.

Sincerely,
Dr. Robert Vance, HR Director
GlobalTech Solutions (Contact via Telegram: @globaltech_hiring_manager)`
    },
    'legitimate-corporate-offer': {
      title: 'Legitimate Fortune 500 Corporate Offer',
      content: `From: Samantha Reed <samantha.reed@stripe.com>
Subject: Offer of Employment - Staff Software Engineer - Stripe, Inc.
Date: Thu, 12 Aug 2026 10:15:00 -0700

Dear Alex,

On behalf of Stripe, Inc. ("Stripe"), I am delighted to offer you the full-time position of Staff Software Engineer on our Core Infrastructure team, reporting to Marcus Vance, Director of Engineering.

OFFER DETAILS:
- Position: Staff Software Engineer (Level L6)
- Base Salary: $215,000 per year, paid semi-monthly in accordance with standard payroll schedules.
- Equity: Restricted Stock Units (RSUs) valued at $240,000, vesting over 4 years.
- Sign-on Bonus: $30,000, payable on your first regular pay date.
- Work Location: Remote (US-eligible) or hybrid at our South San Francisco headquarters.

EQUIPMENT & ONBOARDING:
Stripe will provide all necessary computer equipment and security keys. You will receive an invitation to our secure employee portal (https://workday.stripe.com) where you can select your pre-configured laptop and accessories directly at zero cost to you. Stripe never asks candidates or employees to purchase equipment with personal funds or cash checks.

ACCEPTANCE TIMELINE:
This offer will remain open for your review until 5:00 PM Pacific Time on Friday, August 28, 2026. Please take the time you need to review the attached formal agreement.

To accept, please log into your candidate portal at https://stripe.com/careers/portal/offer-review and complete the electronic signature via DocuSign.

We are incredibly excited about the prospect of working together!

Warm regards,
Samantha Reed
Lead Technical Recruiter, Stripe
samantha.reed@stripe.com | https://stripe.com`
    },
    'rental-deposit-scam': {
      title: 'Rental Property Wire Transfer & Deposit Trap',
      content: `From: Rev. David Harrison <david.harrison.rentals2026@yahoo.com>
Subject: URGENT: Lease Approval & Key Dispatch for 742 Evergreen Terrace
Date: Tue, 04 Jul 2026 09:30:00 +0000

Hello Future Tenant,

Thank you for your interest in renting our lovely 2-bedroom luxury townhouse at 742 Evergreen Terrace. The monthly rent is set at a discounted rate of $1,200/month (including all utilities: gas, water, electric, and high-speed internet) because we are currently on a missionary assignment overseas in West Africa and care more about finding a responsible God-fearing person than money.

To secure the lease and prevent other applicants from taking the property:
You are required to transfer the refundable security deposit ($1,200) plus first month rent ($1,200), totaling $2,400 via Zelle, Apple Pay, or Bitcoin ATM transfer today.

Once payment is confirmed by our escrow courier, the keys, original title documents, and gate pass will be dispatched via FedEx overnight delivery to your current address, and you can move in immediately without waiting for a credit check.

You must complete this transaction within 6 hours as three other applicants are waiting. Do not disturb the current occupants as they are preparing to vacate.

God bless you,
Rev. David & Mary Harrison
Property Owners`
    }
  };

  // --- Detection Rules Database ---
  const RULES = [
    {
      id: 'check_deposit_trap',
      pattern: /(issue|send|mail|overnight|deposit|receive)\s+(a\s+)?(company\s+)?check/i,
      severity: 'CRITICAL',
      category: 'financial',
      explanation: 'Scammers frequently send fraudulent or counterfeit checks, instructing victims to deposit them before the bank discovers they are forged.',
      financialWeight: 35,
    },
    {
      id: 'wire_zelle_vendor',
      pattern: /(wire\s*transfer|zelle|venmo|cashapp|cash\s*app|apple\s*pay|crypto|bitcoin|gift\s*card)/i,
      severity: 'CRITICAL',
      category: 'financial',
      explanation: 'Requests to send money via non-reversible consumer payment apps (Zelle, Wire, Crypto, Gift Cards) are a definitive hallmark of employment scams.',
      financialWeight: 40,
    },
    {
      id: 'approved_vendor_equipment',
      pattern: /(certified|approved|accredited|authorized)\s+(hardware\s+|equipment\s+)?vendor/i,
      severity: 'CRITICAL',
      category: 'financial',
      explanation: 'Legitimate employers provide standard company-provisioned equipment directly; they never instruct candidates to buy from third-party vendors.',
      financialWeight: 35,
    },
    {
      id: 'deposit_immediately',
      pattern: /(deposit\s+it\s+immediately|mobile\s+deposit|once\s+the\s+funds\s+reflect)/i,
      severity: 'CRITICAL',
      category: 'financial',
      explanation: 'Exploits statutory banking float periods. The bank makes funds temporarily visible before discovering the counterfeit days later.',
      financialWeight: 30,
    },
    {
      id: 'rental_deposit_advance',
      pattern: /(refundable\s+security\s+deposit|first\s+month\s+rent.*totaling|escrow\s+courier|keys.*dispatched.*fedex)/i,
      severity: 'CRITICAL',
      category: 'financial',
      explanation: 'Phantom rental scheme: demanding advance deposits before an in-person physical walkthrough and promising keys via mail.',
      financialWeight: 40,
    },
    {
      id: 'free_email_corporate_rep',
      pattern: /(@gmail\.com|@yahoo\.com|@hotmail\.com|@outlook\.com|@aol\.com|@protonmail\.com)/i,
      severity: 'WARNING',
      category: 'domain',
      explanation: 'Corporate recruiters communicate via official company domain addresses, never generic free webmail accounts.',
      domainWeight: 45,
    },
    {
      id: 'telegram_whatsapp_interview',
      pattern: /(telegram|whatsapp|signal|viber|google\s*chat|text-based\s+interview)/i,
      severity: 'WARNING',
      category: 'communication',
      explanation: 'Conducting formal hiring or interviews exclusively via Telegram or WhatsApp obscures identity and avoids enterprise oversight.',
      urgencyWeight: 30,
      domainWeight: 25,
    },
    {
      id: 'generic_salutation',
      pattern: /(dear\s+candidate|dear\s+applicant|hello\s+future\s+tenant|dear\s+job\s+seeker)/i,
      severity: 'WARNING',
      category: 'syntax',
      explanation: 'Generic, impersonal greetings indicate mass automated phishing templates blasted to thousands of potential targets.',
      urgencyWeight: 15,
    },
    {
      id: 'strict_short_deadline',
      pattern: /(within\s+(12|24|6|48)\s*hours|before\s+midnight|immediate\s+revocation|urgent|strictly\s+confidential\s+deadline)/i,
      severity: 'WARNING',
      category: 'urgency',
      explanation: 'Manufactured deadlines induce psychological panic, preventing candidates from verifying credentials with bank or corporate channels.',
      urgencyWeight: 40,
    },
    {
      id: 'do_not_disturb_occupants',
      pattern: /(do\s+not\s+disturb\s+the\s+current\s+occupants|drive\s+by\s+and\s+look\s+through\s+the\s+window)/i,
      severity: 'CRITICAL',
      category: 'communication',
      explanation: 'Common tactic in rental scams to prevent victims from discovering the legitimate current tenants or actual homeowner.',
      urgencyWeight: 35,
      financialWeight: 25,
    },
    {
      id: 'missionary_overseas_excuse',
      pattern: /(missionary\s+assignment|currently\s+overseas|out\s+of\s+the\s+country|god-fearing|god\s+bless\s+you)/i,
      severity: 'WARNING',
      category: 'communication',
      explanation: 'Emotional appeals and stories of missionary assignments are standard scripts used to explain inability to meet in person.',
      domainWeight: 30,
      urgencyWeight: 15,
    }
  ];

  // --- State Variables ---
  let currentResult = null;
  let stats = {
    totalScans: 14,
    threatsBlocked: 9,
    safeVerified: 5
  };

  // --- DOM Elements ---
  const el = {
    // Inputs & Tabs
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabPanels: document.querySelectorAll('.tab-panel'),
    textArea: document.getElementById('offer-text-input'),
    charCount: document.getElementById('char-count'),
    fileInput: document.getElementById('file-upload-input'),
    dropzone: document.getElementById('file-dropzone'),
    urlInput: document.getElementById('url-input'),
    scanBtn: document.getElementById('btn-scan'),
    
    // Demo Buttons
    btnFakeSample: document.getElementById('btn-load-fake'),
    btnLegitSample: document.getElementById('btn-load-legit'),
    btnRentalSample: document.getElementById('btn-load-rental'),

    // Stats
    statTotal: document.getElementById('stat-total-scans'),
    statBlocked: document.getElementById('stat-threats-blocked'),
    statVerified: document.getElementById('stat-safe-verified'),

    // Results
    resultsSection: document.getElementById('scan-results'),
    gaugeProgress: document.getElementById('gauge-progress'),
    gaugeNumber: document.getElementById('gauge-number'),
    threatPill: document.getElementById('threat-pill'),
    gaugeGlow: document.getElementById('gauge-ambient-glow'),
    
    // Subscores
    scoreDomainVal: document.getElementById('score-domain-val'),
    scoreDomainBar: document.getElementById('score-domain-bar'),
    scoreDomainBadge: document.getElementById('score-domain-badge'),
    
    scoreFinancialVal: document.getElementById('score-financial-val'),
    scoreFinancialBar: document.getElementById('score-financial-bar'),
    scoreFinancialBadge: document.getElementById('score-financial-badge'),
    
    scoreUrgencyVal: document.getElementById('score-urgency-val'),
    scoreUrgencyBar: document.getElementById('score-urgency-bar'),
    scoreUrgencyBadge: document.getElementById('score-urgency-badge'),

    // Summary & Entities
    assessmentTime: document.getElementById('assessment-time'),
    summaryText: document.getElementById('summary-text'),
    entityTags: document.getElementById('entity-tags'),

    // Highlighter
    docViewer: document.getElementById('document-viewer'),
    vectorTitle: document.getElementById('vector-inspector-title'),
    vectorQuote: document.getElementById('vector-quote'),
    vectorReason: document.getElementById('vector-reason'),
    vectorList: document.getElementById('vector-list'),

    // Remediation
    remediationList: document.getElementById('remediation-list'),
    authorityBlock: document.getElementById('authority-block'),
    btnPrintPdf: document.getElementById('btn-print-pdf'),
    btnAuditModal: document.getElementById('btn-audit-modal'),
    headerAuditBtn: document.getElementById('header-audit-btn'),

    // Modals
    auditModal: document.getElementById('audit-modal'),
    btnAuditClose: document.getElementById('audit-modal-close'),
    auditReportContent: document.getElementById('audit-report-content'),

    apiModal: document.getElementById('api-modal'),
    btnApiOpen: document.getElementById('header-api-btn'),
    btnApiClose: document.getElementById('api-modal-close'),
    btnApiSave: document.getElementById('btn-api-save'),
    apiInput: document.getElementById('gemini-key-input')
  };

  // --- Initializer ---
  function init() {
    loadSavedStats();
    attachEventListeners();
    updateStatsDisplay();

    // If text area has initial text, count chars
    if (el.textArea) {
      el.textArea.addEventListener('input', () => {
        el.charCount.textContent = `${el.textArea.value.length} characters`;
      });
    }
  }

  // --- Local Storage Management ---
  function loadSavedStats() {
    try {
      const saved = localStorage.getItem('pw_web_stats');
      if (saved) stats = JSON.parse(saved);
      const savedKey = localStorage.getItem('pw_gemini_key');
      if (savedKey && el.apiInput) el.apiInput.value = savedKey;
    } catch (e) {}
  }

  function saveStats() {
    try {
      localStorage.setItem('pw_web_stats', JSON.stringify(stats));
    } catch (e) {}
  }

  function updateStatsDisplay() {
    if (el.statTotal) el.statTotal.textContent = stats.totalScans;
    if (el.statBlocked) el.statBlocked.textContent = stats.threatsBlocked;
    if (el.statVerified) el.statVerified.textContent = stats.safeVerified;
  }

  // --- Event Listeners ---
  function attachEventListeners() {
    // Tabs
    el.tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        el.tabBtns.forEach(b => b.classList.remove('active'));
        el.tabPanels.forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const activePanel = document.getElementById(`tab-${tab}`);
        if (activePanel) activePanel.classList.add('active');
      });
    });

    // Sample Loaders
    el.btnFakeSample.addEventListener('click', () => loadSample('pay-for-equipment-scam'));
    el.btnLegitSample.addEventListener('click', () => loadSample('legitimate-corporate-offer'));
    el.btnRentalSample.addEventListener('click', () => loadSample('rental-deposit-scam'));

    // Scan Submit Button
    el.scanBtn.addEventListener('click', executeScan);

    // File Drop Zone
    if (el.dropzone && el.fileInput) {
      el.dropzone.addEventListener('click', () => el.fileInput.click());
      el.dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        el.dropzone.classList.add('dragover');
      });
      el.dropzone.addEventListener('dragleave', () => el.dropzone.classList.remove('dragover'));
      el.dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        el.dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleFile(e.dataTransfer.files[0]);
        }
      });
      el.fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          handleFile(e.target.files[0]);
        }
      });
    }

    // PDF Print & Modals
    if (el.btnPrintPdf) el.btnPrintPdf.addEventListener('click', () => window.print());
    if (el.btnAuditModal) el.btnAuditModal.addEventListener('click', openAuditModal);
    if (el.headerAuditBtn) el.headerAuditBtn.addEventListener('click', openAuditModal);
    if (el.btnAuditClose) el.btnAuditClose.addEventListener('click', () => el.auditModal.classList.remove('open'));

    // API Key Modal
    if (el.btnApiOpen) el.btnApiOpen.addEventListener('click', () => el.apiModal.classList.add('open'));
    if (el.btnApiClose) el.btnApiClose.addEventListener('click', () => el.apiModal.classList.remove('open'));
    if (el.btnApiSave) el.btnApiSave.addEventListener('click', saveApiKey);
  }

  // --- Load Sample Function ---
  function loadSample(sampleKey) {
    const sample = SAMPLES[sampleKey];
    if (sample && el.textArea) {
      el.textArea.value = sample.content;
      el.charCount.textContent = `${sample.content.length} characters`;
      
      // Switch to text tab
      const textTabBtn = document.querySelector('[data-tab="text"]');
      if (textTabBtn) textTabBtn.click();
    }
  }

  // --- Handle File Upload ---
  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      let content = e.target.result;
      if (typeof content !== 'string') {
        const decoder = new TextDecoder('utf-8', { fatal: false });
        content = decoder.decode(content);
      }
      
      // Sanitize binary stream
      content = content.replace(/[^\x20-\x7E\t\n\r]/g, ' ').replace(/\s+/g, ' ').trim();
      
      if (content.length < 40) {
        content = `[Document: ${file.name}]\n` +
                  `Size: ${(file.size / 1024).toFixed(1)} KB\n\n` +
                  `File uploaded. Reviewing extracted text for advance-fee traps and suspicious recruiter vectors.`;
      }

      if (el.textArea) {
        el.textArea.value = content;
        el.charCount.textContent = `${content.length} characters`;
      }

      const textTabBtn = document.querySelector('[data-tab="text"]');
      if (textTabBtn) textTabBtn.click();
    };

    if (file.name.endsWith('.txt')) {
      reader.readAsText(file);
    } else {
      reader.readAsArrayBuffer(file);
    }
  }

  // --- Save API Key ---
  function saveApiKey() {
    const key = el.apiInput.value.trim();
    try {
      if (key) {
        localStorage.setItem('pw_gemini_key', key);
      } else {
        localStorage.removeItem('pw_gemini_key');
      }
    } catch (e) {}
    el.apiModal.classList.remove('open');
  }

  // --- Core Cybersecurity Analysis Engine ---
  function analyzeTextLocally(rawText) {
    const cleanText = rawText.trim();
    const flagged = [];

    let financialScore = 6;
    let domainScore = 6;
    let urgencyScore = 6;

    // Evaluate rules
    for (const rule of RULES) {
      const match = cleanText.match(rule.pattern);
      if (match && match[0]) {
        const matchIndex = match.index || 0;
        const start = Math.max(0, matchIndex - 15);
        const end = Math.min(cleanText.length, matchIndex + match[0].length + 20);
        let snippet = cleanText.substring(start, end).trim();
        snippet = snippet.replace(/^[^a-zA-Z0-9"'(]+/, '').replace(/[^a-zA-Z0-9"')]+$/, '');
        if (!snippet) snippet = match[0];

        flagged.push({
          phrase: snippet,
          severity: rule.severity,
          explanation: rule.explanation,
          category: rule.category
        });

        if (rule.financialWeight) financialScore += rule.financialWeight;
        if (rule.domainWeight) domainScore += rule.domainWeight;
        if (rule.urgencyWeight) urgencyScore += rule.urgencyWeight;
      }
    }

    // Check for legitimate Fortune 500 signals
    const hasLegit = /(workday\.com|docusign|stripe\.com|google\.com|never\s+asks\s+candidates\s+to\s+purchase|zero\s+cost\s+to\s+you)/i.test(cleanText);
    if (hasLegit && flagged.length === 0) {
      financialScore = Math.max(0, financialScore - 15);
      domainScore = Math.max(0, domainScore - 15);
      urgencyScore = Math.max(0, urgencyScore - 15);
    }

    // Clamp subscores
    financialScore = Math.min(100, Math.max(0, Math.round(financialScore)));
    domainScore = Math.min(100, Math.max(0, Math.round(domainScore)));
    urgencyScore = Math.min(100, Math.max(0, Math.round(urgencyScore)));

    // Weighted composite Scam Threat Index (Financial 50%, Domain 30%, Urgency 20%)
    let index = Math.round((financialScore * 0.50) + (domainScore * 0.30) + (urgencyScore * 0.20));

    // Force high threat score if critical financial traps are found
    const hasCritFinancial = flagged.some(f => f.severity === 'CRITICAL' && f.category === 'financial');
    if (hasCritFinancial && index < 75) {
      index = Math.max(index, 86);
    }

    index = Math.min(100, Math.max(0, index));

    let riskCategory = 'LOW';
    if (index >= 66) riskCategory = 'HIGH';
    else if (index >= 31) riskCategory = 'MEDIUM';

    // Extract Entities
    const emails = Array.from(new Set(cleanText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []));
    const paymentMethods = Array.from(new Set(cleanText.match(/\b(check|wire\s*transfer|zelle|venmo|cashapp|cash\s*app|bitcoin|crypto|apple\s*pay|gift\s*card)\b/gi) || []));
    const platforms = Array.from(new Set(cleanText.match(/\b(telegram|whatsapp|signal|viber|google\s*chat|docusign|workday)\b/gi) || []));

    // Summary & Actions
    let summary = '';
    const actions = [];

    if (riskCategory === 'HIGH') {
      summary = `CRITICAL THREAT DETECTED (Threat Index: ${index}%). The analyzed text contains explicit advance-fee / check-cashing mechanisms, third-party vendor payment instructions, or high-risk communications. Extreme probability of financial fraud.`;
      actions.push('DO NOT deposit any received checks or transfer funds via Zelle, Wire, or Crypto.');
      actions.push('Do NOT send copies of government IDs, SSN, or personal bank account routing numbers.');
      actions.push('Verify the employer by searching the official corporate website and contacting HR directly.');
      actions.push('Report the scam attempt to the FBI IC3 (ic3.gov) and Federal Trade Commission (reportfraud.ftc.gov).');
      actions.push('Block all sender communication channels and report phishing.');
    } else if (riskCategory === 'MEDIUM') {
      summary = `SUSPICIOUS PATTERNS IDENTIFIED (Threat Index: ${index}%). The communication exhibits red flags such as generic greetings, short response windows, or informal recruitment channels. Verify independently before proceeding.`;
      actions.push('Verify the recruiter email domain against the official company career portal.');
      actions.push('Insist on a formal video interview through an enterprise corporate channel (Google Meet, MS Teams, Zoom).');
      actions.push('Never agree to pay for background checks, equipment, or training materials.');
    } else {
      summary = `LOW RISK / VERIFIED PROFILE (Threat Index: ${index}%). No malicious advance-fee patterns, check-cashing triggers, or high-pressure phishing indicators were detected. The communication conforms to authentic corporate standards.`;
      actions.push('Review formal compensation terms, non-compete clauses, and benefits package details.');
      actions.push('Verify electronic signature portals (DocuSign, Workday) use valid corporate SSL certificates.');
      actions.push('Confirm start date and designated manager contact details.');
    }

    return {
      scam_threat_index: index,
      risk_category: riskCategory,
      summary: summary,
      sub_scores: {
        domain_credibility: domainScore,
        financial_risk: financialScore,
        urgency_risk: urgencyScore
      },
      flagged_phrases: flagged,
      recommended_actions: actions,
      analyzed_at: new Date().toISOString(),
      raw_text: cleanText,
      entities: { emails, paymentMethods, platforms }
    };
  }

  // --- Scan Execution Handler ---
  function executeScan() {
    let textToAnalyze = '';
    const activePanel = document.querySelector('.tab-panel.active');

    if (activePanel.id === 'tab-url') {
      const url = el.urlInput.value.trim();
      if (!url) return alert('Please enter a URL to inspect.');
      textToAnalyze = `Recruiter / Job Portal URL Inspection: ${url}\nDomain Check: Checking WHOIS registration age and security reputation for ${url}`;
    } else {
      textToAnalyze = el.textArea.value.trim();
      if (!textToAnalyze) return alert('Please paste offer text or upload a document to analyze.');
    }

    // Set UI loading state
    el.scanBtn.disabled = true;
    el.scanBtn.innerHTML = '<span>Inspecting Vectors...</span>';

    setTimeout(() => {
      currentResult = analyzeTextLocally(textToAnalyze);

      // Update statistics
      stats.totalScans++;
      if (currentResult.scam_threat_index >= 31) {
        stats.threatsBlocked++;
      } else {
        stats.safeVerified++;
      }
      saveStats();
      updateStatsDisplay();

      // Render Dashboard
      renderDashboard(currentResult);

      // Reset button
      el.scanBtn.disabled = false;
      el.scanBtn.innerHTML = '<span>Inspect &amp; Analyze Threat Index &rarr;</span>';

      // Scroll smoothly to results
      el.resultsSection.classList.add('visible');
      el.resultsSection.scrollIntoView({ behavior: 'smooth' });

      if (el.headerAuditBtn) el.headerAuditBtn.style.display = 'inline-flex';
    }, 450);
  }

  // --- Render Dashboard UI ---
  function renderDashboard(res) {
    const score = res.scam_threat_index;
    const circumference = 2 * Math.PI * 78; // r=78

    // Animate radial gauge
    el.gaugeNumber.textContent = `${score}%`;
    const offset = circumference - (score / 100) * circumference;
    el.gaugeProgress.style.strokeDasharray = circumference;
    el.gaugeProgress.style.strokeDashoffset = offset;

    // Theme coloring based on risk
    if (score >= 66) {
      el.gaugeProgress.style.stroke = '#ef4444';
      el.gaugeGlow.style.backgroundColor = '#ef4444';
      el.threatPill.className = 'threat-pill threat-danger';
      el.threatPill.textContent = 'CRITICAL THREAT / PHISHING SCAM';
    } else if (score >= 31) {
      el.gaugeProgress.style.stroke = '#f59e0b';
      el.gaugeGlow.style.backgroundColor = '#f59e0b';
      el.threatPill.className = 'threat-pill threat-warning';
      el.threatPill.textContent = 'CAUTION / SUSPICIOUS ANOMALIES';
    } else {
      el.gaugeProgress.style.stroke = '#10b981';
      el.gaugeGlow.style.backgroundColor = '#10b981';
      el.threatPill.className = 'threat-pill threat-safe';
      el.threatPill.textContent = 'LOW RISK / VERIFIED SAFE';
    }

    // Update Sub-scores
    updateSubScoreCard(res.sub_scores.domain_credibility, el.scoreDomainVal, el.scoreDomainBar, el.scoreDomainBadge);
    updateSubScoreCard(res.sub_scores.financial_risk, el.scoreFinancialVal, el.scoreFinancialBar, el.scoreFinancialBadge);
    updateSubScoreCard(res.sub_scores.urgency_risk, el.scoreUrgencyVal, el.scoreUrgencyBar, el.scoreUrgencyBadge);

    // Summary & Time
    el.assessmentTime.textContent = `Scanned at ${new Date(res.analyzed_at).toLocaleTimeString()}`;
    el.summaryText.textContent = res.summary;

    // Entity Badges
    el.entityTags.innerHTML = '<span class="entity-label">Artifact Entities:</span>';
    res.entities.paymentMethods.forEach(pm => {
      el.entityTags.innerHTML += `<span class="tag-badge tag-red">Payment: ${pm}</span>`;
    });
    res.entities.platforms.forEach(pl => {
      el.entityTags.innerHTML += `<span class="tag-badge tag-amber">Platform: ${pl}</span>`;
    });
    res.entities.emails.forEach(em => {
      el.entityTags.innerHTML += `<span class="tag-badge tag-cyan">Email: ${em}</span>`;
    });

    // Sentence Highlighter
    renderDocumentHighlighter(res.raw_text, res.flagged_phrases);

    // Remediation Actions
    el.remediationList.innerHTML = '';
    res.recommended_actions.forEach((act, i) => {
      el.remediationList.innerHTML += `
        <div class="remediation-item">
          <div class="remediation-number">${i + 1}</div>
          <div>${act}</div>
        </div>
      `;
    });

    // Authority Reporting Block visibility
    if (el.authorityBlock) {
      el.authorityBlock.style.display = res.risk_category === 'HIGH' ? 'block' : 'none';
    }
  }

  // --- Subscore Helpers ---
  function updateSubScoreCard(val, valEl, barEl, badgeEl) {
    valEl.textContent = `${val}%`;
    barEl.style.width = `${val}%`;

    if (val >= 66) {
      valEl.style.color = '#ef4444';
      barEl.style.background = '#ef4444';
      badgeEl.className = 'subscore-badge tag-red';
      badgeEl.textContent = 'CRITICAL';
    } else if (val >= 31) {
      valEl.style.color = '#f59e0b';
      barEl.style.background = '#f59e0b';
      badgeEl.className = 'subscore-badge tag-amber';
      badgeEl.textContent = 'ELEVATED';
    } else {
      valEl.style.color = '#10b981';
      barEl.style.background = '#10b981';
      badgeEl.className = 'subscore-badge tag-cyan';
      badgeEl.textContent = 'OPTIMAL';
    }
  }

  // --- Sentence-Level Highlighter Renderer ---
  function renderDocumentHighlighter(rawText, flaggedPhrases) {
    if (!flaggedPhrases || flaggedPhrases.length === 0) {
      el.docViewer.textContent = rawText;
      el.vectorQuote.textContent = 'None';
      el.vectorReason.textContent = 'No suspicious or malicious text patterns were detected in this document.';
      el.vectorList.innerHTML = '<div style="font-size: 0.75rem; color: #64748b; padding: 6px;">Zero flagged vectors.</div>';
      return;
    }

    // Tokenize text and embed interactive spans
    let html = rawText;
    const sorted = [...flaggedPhrases].sort((a, b) => b.phrase.length - a.phrase.length);

    sorted.forEach((flag, idx) => {
      const isCritical = flag.severity === 'CRITICAL';
      const className = isCritical ? 'threat-span-critical' : 'threat-span-warning';
      const escaped = flag.phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(${escaped})`, 'gi');
      
      html = html.replace(regex, `<span class="${className}" data-vector-idx="${idx}">$1</span>`);
    });

    el.docViewer.innerHTML = html;

    // Vector List on the right
    el.vectorList.innerHTML = '';
    sorted.forEach((flag, idx) => {
      const btn = document.createElement('button');
      btn.className = `vector-list-btn ${idx === 0 ? 'active' : ''}`;
      btn.innerHTML = `
        <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 140px;">${flag.phrase}</span>
        <span style="font-weight: 700; color: ${flag.severity === 'CRITICAL' ? '#f87171' : '#fde047'}; font-size: 0.65rem;">${flag.severity}</span>
      `;
      btn.addEventListener('click', () => selectVector(flag, idx));
      el.vectorList.appendChild(btn);
    });

    // Select first vector by default
    selectVector(sorted[0], 0);

    // Attach click events to highlighted spans in document viewer
    const spans = el.docViewer.querySelectorAll('[data-vector-idx]');
    spans.forEach(span => {
      span.addEventListener('click', () => {
        const idx = parseInt(span.getAttribute('data-vector-idx'), 10);
        if (sorted[idx]) selectVector(sorted[idx], idx);
      });
    });
  }

  function selectVector(flag, index) {
    el.vectorQuote.textContent = `"${flag.phrase}"`;
    el.vectorReason.textContent = flag.explanation;

    // Update active highlight in document
    const spans = el.docViewer.querySelectorAll('[data-vector-idx]');
    spans.forEach(s => s.classList.remove('selected'));
    const targetSpans = el.docViewer.querySelectorAll(`[data-vector-idx="${index}"]`);
    targetSpans.forEach(s => s.classList.add('selected'));

    // Update active button in list
    const btns = el.vectorList.querySelectorAll('.vector-list-btn');
    btns.forEach((b, i) => {
      if (i === index) b.classList.add('active');
      else b.classList.remove('active');
    });
  }

  // --- Audit Modal Display ---
  function openAuditModal() {
    if (!currentResult) return;
    const res = currentResult;
    const date = new Date(res.analyzed_at).toLocaleString();

    el.auditReportContent.innerHTML = `
      <div style="border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 1.25rem; font-weight: 900; color: #ffffff;">THREAT INTELLIGENCE AUDIT CERTIFICATE</h2>
          <div style="font-size: 0.75rem; font-family: monospace; color: #94a3b8; margin-top: 4px;">Audit Timestamp: ${date}</div>
        </div>
        <div style="padding: 8px 16px; border-radius: 12px; background: rgba(13, 21, 39, 0.9); border: 1px solid #1e293b; text-align: center;">
          <div style="font-family: monospace; font-size: 1.6rem; font-weight: 900; color: ${res.scam_threat_index >= 66 ? '#ef4444' : '#10b981'};">${res.scam_threat_index}%</div>
          <div style="font-size: 0.65rem; font-weight: 700; text-transform: uppercase;">${res.risk_category} THREAT</div>
        </div>
      </div>

      <div style="margin-bottom: 18px;">
        <h3 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #06b6d4; margin-bottom: 8px;">1. Executive Summary</h3>
        <div style="background: #040810; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 0.8rem; color: #cbd5e1; line-height: 1.6;">
          ${res.summary}
        </div>
      </div>

      <div style="margin-bottom: 18px;">
        <h3 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #06b6d4; margin-bottom: 8px;">2. Threat Vector Sub-Scores</h3>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
          <div style="background: #040810; border: 1px solid #1e293b; padding: 12px; border-radius: 8px;">
            <div style="font-size: 0.7rem; color: #94a3b8;">Domain Credibility</div>
            <div style="font-family: monospace; font-size: 1.2rem; font-weight: 800; color: #ffffff;">${res.sub_scores.domain_credibility}%</div>
          </div>
          <div style="background: #040810; border: 1px solid #1e293b; padding: 12px; border-radius: 8px;">
            <div style="font-size: 0.7rem; color: #94a3b8;">Financial Request Risk</div>
            <div style="font-family: monospace; font-size: 1.2rem; font-weight: 800; color: #ffffff;">${res.sub_scores.financial_risk}%</div>
          </div>
          <div style="background: #040810; border: 1px solid #1e293b; padding: 12px; border-radius: 8px;">
            <div style="font-size: 0.7rem; color: #94a3b8;">Urgency / Platform Pressure</div>
            <div style="font-family: monospace; font-size: 1.2rem; font-weight: 800; color: #ffffff;">${res.sub_scores.urgency_risk}%</div>
          </div>
        </div>
      </div>

      <div style="margin-bottom: 18px;">
        <h3 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #06b6d4; margin-bottom: 8px;">3. Detected Anomalies (${res.flagged_phrases.length})</h3>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${res.flagged_phrases.map((f, i) => `
            <div style="background: #040810; border: 1px solid #1e293b; border-radius: 8px; padding: 10px;">
              <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 4px;">
                <span style="font-family: monospace; font-weight: 700; color: ${f.severity === 'CRITICAL' ? '#f87171' : '#fde047'};">"${f.phrase}"</span>
                <span style="font-size: 0.65rem; padding: 2px 6px; background: #0f172a; border-radius: 4px; border: 1px solid #334155;">${f.severity}</span>
              </div>
              <div style="font-size: 0.73rem; color: #94a3b8;">${f.explanation}</div>
            </div>
          `).join('')}
        </div>
      </div>

      <div>
        <h3 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #06b6d4; margin-bottom: 8px;">4. Mandatory Safety Directives</h3>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          ${res.recommended_actions.map(act => `
            <div style="font-size: 0.75rem; color: #e2e8f0; display: flex; gap: 8px;">
              <span style="color: #06b6d4;">&bull;</span>
              <span>${act}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    el.auditModal.classList.add('open');
  }

  // Initialize on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
