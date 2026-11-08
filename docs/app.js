/* Email Security Auditor - static GitHub Pages version
 * All DNS lookups run in the browser via DNS-over-HTTPS (Google, 8.8.8.8).
 */
const DNS_URL = 'https://dns.google/resolve';
const RR_TYPES = { TXT: 16, MX: 15, CNAME: 5, PTR: 12 };

const DKIM_SELECTORS = ['default', 'selector1', 'selector2', 'selector3', 'key1', 'key2',
    'dkim', 'dkim1', 'dkim2', 'TEN', 'TEN2', 'google', 'microsoft'];
const DKIM_CNAME_SELECTORS = ['default', 'selector1', 'selector2', 'selector3', 'key1', 'key2',
    'dkim', 'dkim1', 'dkim2', 'TEN', 'TEN2', 'mail', 'google', 'microsoft'];
const COMMON_CNAMES = ['mail', 'smtp', 'imap', 'pop3', 'webmail', 'autodiscover', 'autoconfig',
    'mta', 'ftp', 'www', 'portal', 'vle', 'moodle', 'canvas', 'blackboard', 'terms', 'admin',
    'remote', 'arbor', 'arbor-sync', 'sims', 'sims-api', 'capita', 'Parent', 'ParentPortal',
    'Staff', 'school', 'cloud', 'api', 'drive', 'files', 'office365', 'o365', 'outlook',
    'teams', 'sharepoint', 'sso', 'id', 'login', 'auth'];

async function dnsQuery(name, type) {
    try {
        const res = await fetch(`${DNS_URL}?name=${encodeURIComponent(name)}&type=${RR_TYPES[type]}`);
        if (!res.ok) return [];
        const data = await res.json();
        return (data.Answer || []).filter(a => a.type === RR_TYPES[type]).map(a => a.data);
    } catch { return []; }
}

function cleanTxt(txt) {
    return txt.replace(/^"|"$/g, '').replace(/" "/g, '');
}

function analyzeSpf(txt) {
    const warnings = [];
    const lower = txt.toLowerCase();
    if (lower.includes('~all') && !lower.includes('-all'))
        warnings.push("Using '~all' (softfail) instead of '-all' (hardfail) - less secure");
    if (lower.includes('+all'))
        warnings.push("Using '+all' - allows ANY server to send email (very insecure!)");
    if (!lower.includes('include:') && !lower.includes('ip4:') && !lower.includes('ip6:'))
        warnings.push('SPF record has no authorized servers - may be misconfigured');
    if ((txt.match(/include:/g) || []).length > 10)
        warnings.push('SPF record has too many includes - may hit lookup limit (10 max)');
    return warnings;
}

function detectProvider(txt) {
    const lower = txt.toLowerCase();
    if (lower.includes('outlook.com') || lower.includes('onmicrosoft.com') || lower.includes('sharpgear'))
        return 'Microsoft 365';
    if (lower.includes('google.com')) return 'Google Workspace';
    if (lower.includes('mimecast')) return 'Mimecast';
    if (lower.includes('proofpoint') || lower.includes('pphosted')) return 'Proofpoint';
    if (lower.includes('barracuda')) return 'Barracuda';
    if (lower.includes('symantec') || lower.includes('messagelabs')) return 'Symantec/Broadcom';
    return 'Unknown / On-Premise';
}

async function auditDomain(domain) {
    const [spfTxt, mxRaw, dmarcTxt] = await Promise.all([
        dnsQuery(domain, 'TXT'),
        dnsQuery(domain, 'MX'),
        dnsQuery(`_dmarc.${domain}`, 'TXT')
    ]);

    // SPF
    let spf_rec = 'No SPF record found', service = 'Unknown / On-Premise', spf_v = false, spf_warnings = [];
    for (const raw of spfTxt) {
        const txt = cleanTxt(raw);
        if (txt.includes('v=spf1')) {
            spf_rec = txt; spf_v = true;
            service = detectProvider(txt);
            spf_warnings = analyzeSpf(txt);
            break;
        }
    }

    // MX
    let mx_records = mxRaw.map(d => d.split(/\s+/)[1].replace(/\.$/, ''));
    if (!mx_records.length) mx_records = ['No MX records found'];

    // DKIM
    const dkimAnswers = await Promise.all(
        DKIM_SELECTORS.map(sel => dnsQuery(`${sel}._domainkey.${domain}`, 'TXT').then(a => [sel, a]))
    );
    let dkim_records = [];
    let dkim_selectors = [];
    for (const [sel, answers] of dkimAnswers) {
        for (const raw of answers) {
            const txt = cleanTxt(raw);
            const p = txt.match(/p=([^;\s]*)/i);
            if (p && p[1].length > 0 && (txt.includes('v=DKIM1') || txt.includes('k=rsa'))) {
                dkim_records.push(`${sel}._domainkey.${domain} -> ${txt.slice(0, 80)}...`);
                dkim_selectors.push(sel);
            }
        }
    }
    if (!dkim_records.length) dkim_records = ['No DKIM TXT records found'];

    // DMARC
    let dmarc_rec = 'No DMARC record found', rua = 'Not Configured', policy = 'Missing', dmarc_v = false;
    for (const raw of dmarcTxt) {
        const txt = cleanTxt(raw);
        if (txt.includes('v=DMARC1')) {
            dmarc_rec = txt; dmarc_v = true;
            const lower = txt.toLowerCase();
            if (lower.includes('rua=mailto:'))
                rua = lower.split('rua=mailto:')[1].split(';')[0];
            if (lower.includes('p=quarantine')) policy = 'Quarantine';
            else if (lower.includes('p=reject')) policy = 'Reject';
            else if (lower.includes('p=none')) policy = 'None';
            break;
        }
    }

    // CNAMEs
    const cnameTargets = [
        ...DKIM_CNAME_SELECTORS.map(sel => `${sel}._domainkey.${domain}`),
        ...COMMON_CNAMES.map(sub => `${sub}.${domain}`)
    ];
    const cnameAnswers = await Promise.all(cnameTargets.map(n => dnsQuery(n, 'CNAME').then(a => [n, a])));
    let cname_records = [];
    for (const [name, answers] of cnameAnswers)
        for (const target of answers)
            cname_records.push(`${name} -> ${target.replace(/\.$/, '')}`);
    if (!cname_records.length) cname_records = ['No CNAME records found'];

    const result = {
        domain, provider: service, report_to: rua, policy,
        spf: { record: spf_rec, valid: spf_v, warnings: spf_warnings },
        mx: mx_records, dkim: dkim_records, dkim_selectors,
        dmarc: { record: dmarc_rec, valid: dmarc_v },
        cname: cname_records
    };
    result.score = scoreAudit(result);
    return result;
}

/* ---------- Scoring (0-100) ---------- */
function scoreAudit(d) {
    let score = 0, breakdown = [];

    let s = 0;
    if (d.dmarc.valid) {
        if (d.policy === 'Reject') s = 40;
        else if (d.policy === 'Quarantine') s = 30;
        else s = 15;
    }
    score += s; breakdown.push(['DMARC', s, 40]);

    s = 0;
    if (d.spf.valid) {
        const lower = d.spf.record.toLowerCase();
        if (lower.includes('+all')) s = 0;
        else if (lower.includes('-all')) s = 20;
        else s = 12;
        s = Math.max(0, s - 5 * d.spf.warnings.filter(w => !w.includes('~all')).length);
    }
    score += s; breakdown.push(['SPF', s, 20]);

    s = d.dkim_selectors.length > 0 ? 20 : 0;
    score += s; breakdown.push(['DKIM', s, 20]);

    s = (d.report_to !== 'Not Configured' && d.dmarc.valid) ? 10 : 0;
    score += s; breakdown.push(['DMARC Reports (rua)', s, 10]);

    let provider_dkim = '';
    if (d.provider === 'Google Workspace')
        provider_dkim = d.dkim_selectors.includes('google')
            ? 'DKIM enabled in Google Admin console'
            : 'DKIM NOT enabled (google._domainkey missing)';
    else if (d.provider === 'Microsoft 365')
        provider_dkim = (d.dkim_selectors.includes('selector1') || d.dkim_selectors.includes('selector2'))
            ? 'DKIM enabled in M365'
            : 'DKIM NOT enabled (selector1/selector2 missing)';

    const status = score >= 80 ? 'Protected' : score >= 50 ? 'Partial' : score >= 25 ? 'Monitoring' : 'Critical';
    return { total: score, breakdown, status, provider_dkim };
}

/* ---------- Bulk audit ---------- */
async function auditAll() {
    const raw = document.getElementById('bulkIn').value;
    const domains = [...new Set(raw.split(/[\s,;]+/)
        .map(s => s.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase())
        .filter(Boolean))];
    if (!domains.length) return alert('Please enter at least one domain (one per line)');

    const btn = document.getElementById('bulkBtn');
    btn.disabled = true; btn.textContent = 'Auditing...';
    window.bulkData = [];
    document.getElementById('bulkResults').style.display = 'none';
    document.getElementById('detailSection').style.display = 'none';
    document.getElementById('bulkProgress').style.display = 'block';
    document.getElementById('bulkBar').style.width = '0%';

    const BATCH = 3;
    for (let i = 0; i < domains.length; i += BATCH) {
        const batch = await Promise.all(domains.slice(i, i + BATCH).map(auditDomain));
        window.bulkData.push(...batch);
        const pct = Math.round(window.bulkData.length / domains.length * 100);
        document.getElementById('bulkBar').style.width = pct + '%';
        document.getElementById('bulkProgressText').innerText =
            `Audited ${window.bulkData.length} of ${domains.length} domains (${pct}%)`;
    }

    sortBulk('score', true);
    document.getElementById('bulkResults').style.display = 'block';
    document.getElementById('bulkProgress').style.display = 'none';
    btn.disabled = false; btn.textContent = 'Audit All Domains';
}

const POLICY_RANK = { Missing: 0, None: 1, Quarantine: 2, Reject: 3 };
const STATUS_RANK = { Critical: 0, Monitoring: 1, Partial: 2, Protected: 3 };
const STATUS_CHIP = { Protected: 'green', Partial: 'blue', Monitoring: 'amber', Critical: 'red' };
const STATUS_COLOR = { Protected: '#34d399', Partial: '#60a5fa', Monitoring: '#fbbf24', Critical: '#f87171' };
let bulkSortKey = 'score', bulkSortDir = -1;

function sortValue(d, key) {
    switch (key) {
        case 'domain': return d.domain;
        case 'provider': return d.provider;
        case 'spf': return d.spf.valid ? 1 : 0;
        case 'dkim': return d.dkim_selectors.length;
        case 'policy': return POLICY_RANK[d.policy] ?? 0;
        case 'rua': return d.report_to !== 'Not Configured' ? 1 : 0;
        case 'score': return d.score.total;
        case 'status': return STATUS_RANK[d.score.status];
    }
}

function sortBulk(key, keepDir) {
    if (bulkSortKey === key) { if (!keepDir) bulkSortDir *= -1; }
    else { bulkSortKey = key; bulkSortDir = key === 'domain' || key === 'provider' ? 1 : -1; }
    window.bulkData.sort((a, b) => {
        const va = sortValue(a, key), vb = sortValue(b, key);
        return (va > vb ? 1 : va < vb ? -1 : 0) * bulkSortDir;
    });
    renderBulk();
}

function statusBadge(status) {
    return `<span class="chip ${STATUS_CHIP[status]}">${status}</span>`;
}

function mark(v) { return v ? '<span class="ok">&#10003;</span>' : '<span class="no">&#10007;</span>'; }

function renderBulk() {
    const rows = window.bulkData.map((d, i) => `
        <tr onclick="showDetail(${i})">
            <td><b>${d.domain}</b></td>
            <td>${d.provider}</td>
            <td>${mark(d.spf.valid)}</td>
            <td>${mark(d.dkim_selectors.length > 0)}</td>
            <td>${d.policy}</td>
            <td>${mark(d.report_to !== 'Not Configured')}</td>
            <td><b>${d.score.total}</b>/100</td>
            <td>${statusBadge(d.score.status)}</td>
        </tr>`).join('');
    document.getElementById('bulkBody').innerHTML = rows;

    const counts = { Protected: 0, Partial: 0, Monitoring: 0, Critical: 0 };
    const providers = {};
    window.bulkData.forEach(d => { counts[d.score.status]++; providers[d.provider] = (providers[d.provider] || 0) + 1; });
    document.getElementById('portfolioStats').innerHTML =
        `<span class="chip grey">${window.bulkData.length} domains audited</span>` +
        Object.entries(counts).map(([k, v]) => `<span class="chip ${STATUS_CHIP[k]}">${v} ${k}</span>`).join('') +
        Object.entries(providers).map(([k, v]) => `<span class="chip grey">${v} &times; ${k}</span>`).join('');
}

function showDetail(i) {
    const data = window.bulkData[i];
    window.auditData = data;
    renderAudit(data);
    document.getElementById('detailSection').style.display = 'block';
    document.querySelectorAll('#bulkBody tr').forEach((tr, j) => tr.classList.toggle('active', j === i));
    document.getElementById('detailSection').scrollIntoView({ behavior: 'smooth' });
}

function exportBulkCSV() {
    if (!window.bulkData || !window.bulkData.length) return alert('No bulk data to export');
    const header = 'Domain,Provider,SPF Valid,SPF Record,SPF Warnings,DKIM Selectors,DKIM For Provider,DMARC Policy,DMARC Report To,Score,Status\n';
    const esc = v => `"${String(v).replace(/"/g, '""')}"`;
    const rows = window.bulkData.map(d => [
        d.domain, d.provider, d.spf.valid, d.spf.record, d.spf.warnings.join('; '),
        d.dkim_selectors.join('; '), d.score.provider_dkim, d.policy, d.report_to,
        d.score.total, d.score.status
    ].map(esc).join(','));
    const blob = new Blob([header + rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'email_security_bulk_report.csv';
    a.click();
    URL.revokeObjectURL(url);
}

function exportBulkJSON() {
    if (!window.bulkData || !window.bulkData.length) return alert('No bulk data to export');
    const blob = new Blob([JSON.stringify(window.bulkData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'email_security_bulk_report.json';
    a.click();
    URL.revokeObjectURL(url);
}

async function ptrLookup(ip) {
    let name;
    if (ip.includes(':')) {
        const head = ip.split('::')[0].split(':');
        const tail = ip.split('::')[1] ? ip.split('::')[1].split(':') : [];
        const groups = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
        const full = groups.map(g => g.padStart(4, '0')).join('');
        name = full.split('').reverse().join('.') + '.ip6.arpa';
    } else {
        name = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    }
    const answers = await dnsQuery(name, 'PTR');
    return answers.length ? answers[0].replace(/\.$/, '') : ip;
}

async function parseRuaXml(text) {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new Error('Invalid XML file');
    const records = doc.getElementsByTagName('record');
    const rows = [];
    for (const rec of records) {
        const q = tag => rec.getElementsByTagName(tag)[0];
        const ip = q('source_ip') ? q('source_ip').textContent.trim() : '';
        rows.push({
            source_server: ip ? await ptrLookup(ip) : 'Unknown',
            count: q('count') ? q('count').textContent.trim() : '',
            spf: q('spf') ? (q('spf').getAttribute('result') || q('spf').textContent.trim() || 'none') : 'none',
            dkim: q('dkim') ? (q('dkim').getAttribute('result') || q('dkim').textContent.trim() || 'none') : 'none',
            disposition: q('disposition') ? (q('disposition').getAttribute('policy') || q('disposition').textContent.trim() || 'none') : 'none'
        });
    }
    return rows;
}

/* ---------- UI ---------- */
async function runAudit() {
    const domain = document.getElementById('domainIn').value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain) return alert('Please enter a domain');

    const btn = document.getElementById('auditBtn');
    btn.disabled = true; btn.textContent = 'Auditing...';
    document.getElementById('detailSection').style.display = 'none';

    try {
        const data = await auditDomain(domain);
        window.auditData = data;
        renderAudit(data);
        document.getElementById('detailSection').style.display = 'block';
        document.getElementById('detailSection').scrollIntoView({ behavior: 'smooth' });
    } catch (e) {
        alert('Audit failed: ' + e.message);
    } finally {
        btn.disabled = false; btn.textContent = 'Audit Domain';
    }
}

function renderAudit(data) {
    const color = STATUS_COLOR[data.score.status];
    document.getElementById('resTitle').innerText = 'Security Audit: ' + data.domain;
    document.getElementById('summaryBox').innerHTML = `
        <div class="score-hero">
            <div class="score-ring" style="--pct:${data.score.total}; --color:${color}">
                <span class="num">${data.score.total}<small>/100</small></span>
            </div>
            <div class="score-meta">
                <div class="domain-name">${data.domain} &nbsp;${statusBadge(data.score.status)}</div>
                <div class="stat-grid">
                    <div class="stat"><b>Email Host</b><span>${data.provider}</span></div>
                    <div class="stat"><b>DMARC Policy</b><span>${data.policy}</span></div>
                    <div class="stat"><b>Reports To</b><span>${data.report_to}</span></div>
                    <div class="stat"><b>SPF</b><span>${data.spf.valid ? 'Found' : 'Missing'}</span></div>
                    <div class="stat"><b>DKIM</b><span>${data.dkim_selectors.length ? data.dkim_selectors.length + ' selector(s)' : 'None'}</span></div>
                </div>
            </div>
        </div>`;

    let rec = '';
    if (data.score.provider_dkim)
        rec += `<span class='${data.score.provider_dkim.startsWith('DKIM NOT') ? 'text-danger' : 'text-success'}'><b>${data.provider}:</b></span> ${data.score.provider_dkim}<br><br>`;

    if (!data.dmarc.valid) {
        rec += "<span class='text-danger'>🔴 <b>CRITICAL:</b></span> No DMARC record found. Without DMARC, your domain is vulnerable to email spoofing attacks. <b>Action:</b> Create a DMARC record immediately (start with 'p=none' for monitoring).";
    } else if (data.policy === 'None') {
        rec += "<span class='text-warning'>⚠️ <b>MONITORING ONLY:</b></span> DMARC is set to 'p=none' which only monitors email without taking action. <b>Action:</b> Review your DMARC reports, then upgrade to 'p=quarantine' after confirming legitimate email sources are properly configured.";
    } else if (data.policy === 'Quarantine') {
        rec += "<span class='text-info'>🔵 <b>PARTIAL PROTECTION:</b></span> DMARC policy is set to quarantine suspicious emails. <b>Action:</b> Consider upgrading to 'p=reject' once you're confident all legitimate email sources are authorized.";
    } else if (data.policy === 'Reject') {
        rec += "<span class='text-success'>✅ <b>FULL PROTECTION:</b></span> DMARC policy is set to reject unauthorized emails. Your domain is well protected against spoofing.";
    }

    if (!data.spf.valid)
        rec += "<br><br><span class='text-danger'>⚠️ <b>SPF MISSING:</b></span> No valid SPF record found. <b>Action:</b> Add an SPF record to authorize your email servers.";

    if (data.cname && data.cname.length > 0 && !data.cname[0].includes('No'))
        rec += `<br><br><span class='text-info'>ℹ️ <b>CNAME RECORDS:</b></span> ${data.cname.length} email-related CNAME record(s) found. Verify these are correct for your email provider.`;

    if (data.spf.warnings && data.spf.warnings.length > 0)
        rec += "<br><br><span class='text-warning'>⚠️ <b>SPF WARNINGS:</b></span><br>• " + data.spf.warnings.join('<br>• ');

    if (!data.mx || data.mx[0].includes('No'))
        rec += "<br><br><span class='text-danger'>⚠️ <b>MX MISSING:</b></span> No MX records found. Email may not be configured.";

    if (data.dkim_selectors.length > 0)
        rec += `<br><br><span class='text-success'>✅ <b>DKIM CONFIGURED:</b></span> ${data.dkim_selectors.length} DKIM selector(s) found (${data.dkim_selectors.join(', ')}).`;
    else if (data.spf.valid)
        rec += "<br><br><span class='text-warning'>⚠️ <b>DKIM MISSING:</b></span> No DKIM records found. Consider adding DKIM for better email security.";

    document.getElementById('printDate').innerText = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    document.getElementById('printRec').innerHTML = '<h5><b>Executive Summary</b></h5>' + rec;
    document.getElementById('recText').innerHTML = rec;
    document.getElementById('mxRec').innerText = data.mx.join('\n');
    document.getElementById('spfRec').innerText = data.spf.record;
    document.getElementById('spfWarnings').innerHTML = data.spf.warnings.length > 0
        ? "<small class='text-warning'>⚠️ " + data.spf.warnings.join('<br>⚠️ ') + '</small>'
        : '';
    document.getElementById('dmarcRec').innerText = data.dmarc.record;
    document.getElementById('dkimRec').innerText = data.dkim.join('\n');
    document.getElementById('cnameRec').innerText = data.cname.join('\n');
}

async function uploadRUA() {
    const input = document.getElementById('ruaFile');
    if (!input.files.length) return alert('Please select a DMARC XML report');
    try {
        const text = await input.files[0].text();
        const rows = await parseRuaXml(text);
        if (!rows.length) return alert('No records found in XML');
        document.getElementById('ruaBody').innerHTML = rows.map(r =>
            `<tr><td>${r.source_server}</td><td>${r.count}</td><td>${r.spf}</td><td>${r.dkim}</td><td>${r.disposition}</td></tr>`
        ).join('');
        document.getElementById('ruaSection').style.display = 'block';
    } catch (e) {
        alert('RUA parse failed: ' + e.message);
    }
}

function exportJSON() {
    if (!window.auditData) return alert('No audit data to export');
    const blob = new Blob([JSON.stringify(window.auditData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = window.auditData.domain + '_audit.json';
    a.click();
    URL.revokeObjectURL(url);
}

function exportCSV() {
    if (!window.auditData) return alert('No audit data to export');
    const d = window.auditData;
    let csv = 'Field,Value\n';
    csv += `Domain,${d.domain}\n`;
    csv += `Email Provider,${d.provider}\n`;
    csv += `Security Score,${d.score.total}/100 (${d.score.status})\n`;
    csv += `DMARC Policy,${d.policy}\n`;
    csv += `DMARC Report To,${d.report_to}\n`;
    csv += `SPF Valid,${d.spf.valid}\n`;
    csv += `SPF Record,"${d.spf.record.replace(/"/g, '""')}"\n`;
    if (d.spf.warnings.length > 0)
        csv += `SPF Warnings,"${d.spf.warnings.join('; ')}"\n`;
    csv += `MX Records,"${d.mx.join('; ')}"\n`;
    csv += `DKIM Records,"${d.dkim.join('; ')}"\n`;
    csv += `CNAME Records,"${d.cname.join('; ')}"\n`;

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = d.domain + '_audit.csv';
    a.click();
    URL.revokeObjectURL(url);
}
