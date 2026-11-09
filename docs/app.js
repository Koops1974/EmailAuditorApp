/* Email Security Auditor - static GitHub Pages version
 * All DNS lookups run in the browser via DNS-over-HTTPS (Google, 8.8.8.8).
 */
const DNS_URL = 'https://dns.google/resolve';
const RR_TYPES = { TXT: 16, MX: 15, CNAME: 5, PTR: 12, NS: 2 };

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

function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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

const DNS_HOSTS = [
    ['cloudflare', 'Cloudflare'], ['awsdns', 'AWS Route 53'], ['microsoftdns', 'Azure DNS'],
    ['dnsazure', 'Azure DNS'], ['azure-dns', 'Azure DNS'], ['googledomains', 'Google Domains'], ['gsdns', 'Google Cloud DNS'],
    ['godaddy', 'GoDaddy'], ['domaincontrol', 'GoDaddy'], ['afternic', 'Afternic'],
    ['dnsowl', 'Namecheap'], ['registrar-servers', 'Namecheap'], ['cscdns', 'CSC Global'],
    ['ultradns', 'Verizon UltraDNS'], ['cloudns', 'Oracle Dyn'], ['dnsmadeeasy', 'DNS Made Easy'],
    ['fasthosts', 'Fasthosts'], ['ionos', 'IONOS'], ['ui-dns', 'IONOS'], ['123-reg', '123 Reg'], ['netnames', 'Netnames'],
    ['namesprotection', 'Namesprotection'], ['krystal', 'Krystal'], ['heartinternet', 'Heart Internet'],
    ['ns1.net', 'NS1'], ['dnsv1', 'Akamai'], ['squarespace', 'Squarespace'], ['parastone', 'Parastone'],
    ['ifl.net', 'RM (Research Machines)'], ['rmplc', 'RM (Research Machines)'],
    ['livedns', 'Schools Broadband'],
    ['anycast', 'ClouDNS'], ['brandedns', 'CentralNic'], ['nomin', 'Nominet'], ['zoneedit', 'ZoneEdit']
];

function detectDnsHost(ns) {
    const joined = ns.join(' ').toLowerCase();
    for (const [k, v] of DNS_HOSTS) if (joined.includes(k)) return v;
    if (ns.length) {
        const p = ns[0].split('.');
        return p.length >= 2 ? p.slice(-2).join('.') : ns[0];
    }
    return 'Unknown';
}

async function auditDomain(domain) {
    const [spfTxt, mxRaw, dmarcTxt, nsRaw] = await Promise.all([
        dnsQuery(domain, 'TXT'),
        dnsQuery(domain, 'MX'),
        dnsQuery(`_dmarc.${domain}`, 'TXT'),
        dnsQuery(domain, 'NS')
    ]);

    // Nameservers / DNS host
    const ns_records = nsRaw.map(d => d.replace(/\.$/, ''));
    const dns_host = detectDnsHost(ns_records);

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
        domain, provider: service, report_to: rua, policy, dns_host,
        ns: ns_records,
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
    score += s; breakdown.push(['DMARC Policy', s, 40]);

    s = 0;
    if (d.spf.valid) {
        const lower = d.spf.record.toLowerCase();
        if (lower.includes('+all')) s = 0;
        else if (lower.includes('-all')) s = 20;
        else s = 12;
        s = Math.max(0, s - 5 * d.spf.warnings.filter(w => !w.includes('~all')).length);
    }
    score += s; breakdown.push(['SPF Hardening', s, 20]);

    s = d.dkim_selectors.length > 0 ? 20 : 0;
    score += s; breakdown.push(['DKIM Signing', s, 20]);

    s = (d.report_to !== 'Not Configured' && d.dmarc.valid) ? 10 : 0;
    score += s; breakdown.push(['DMARC Reporting (rua)', s, 10]);

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

function buildRecommendation(d) {
    let rec = '';
    if (d.score.provider_dkim)
        rec += `<span class='${d.score.provider_dkim.startsWith('DKIM NOT') ? 'text-danger' : 'text-success'}'><b>${d.provider}:</b></span> ${d.score.provider_dkim}<br><br>`;

    if (!d.dmarc.valid) {
        rec += "<span class='text-danger'>🔴 <b>CRITICAL:</b></span> No DMARC record found. Without DMARC, your domain is vulnerable to email spoofing attacks. <b>Action:</b> Create a DMARC record immediately (start with 'p=none' for monitoring).";
    } else if (d.policy === 'None') {
        rec += "<span class='text-warning'>⚠️ <b>MONITORING ONLY:</b></span> DMARC is set to 'p=none' which only monitors email without taking action. <b>Action:</b> Review your DMARC reports, then upgrade to 'p=quarantine' after confirming legitimate email sources are properly configured.";
    } else if (d.policy === 'Quarantine') {
        rec += "<span class='text-info'>🔵 <b>PARTIAL PROTECTION:</b></span> DMARC policy is set to quarantine suspicious emails. <b>Action:</b> Consider upgrading to 'p=reject' once you're confident all legitimate email sources are authorized.";
    } else if (d.policy === 'Reject') {
        rec += "<span class='text-success'>✅ <b>FULL PROTECTION:</b></span> DMARC policy is set to reject unauthorized emails. Your domain is well protected against spoofing.";
    }

    if (!d.spf.valid)
        rec += "<br><br><span class='text-danger'>⚠️ <b>SPF MISSING:</b></span> No valid SPF record found. <b>Action:</b> Add an SPF record to authorize your email servers.";

    if (d.cname && d.cname.length > 0 && !d.cname[0].includes('No'))
        rec += `<br><br><span class='text-info'>ℹ️ <b>CNAME RECORDS:</b></span> ${d.cname.length} email-related CNAME record(s) found. Verify these are correct for your email provider.`;

    if (d.spf.warnings && d.spf.warnings.length > 0)
        rec += "<br><br><span class='text-warning'>⚠️ <b>SPF WARNINGS:</b></span><br>• " + d.spf.warnings.join('<br>• ');

    if (!d.mx || d.mx[0].includes('No'))
        rec += "<br><br><span class='text-danger'>⚠️ <b>MX MISSING:</b></span> No MX records found. Email may not be configured.";

    if (d.dkim_selectors.length > 0)
        rec += `<br><br><span class='text-success'>✅ <b>DKIM CONFIGURED:</b></span> ${d.dkim_selectors.length} DKIM selector(s) found (${d.dkim_selectors.join(', ')}).`;
    else if (d.spf.valid)
        rec += "<br><br><span class='text-warning'>⚠️ <b>DKIM MISSING:</b></span> No DKIM records found. Consider adding DKIM for better email security.";

    return rec;
}

/* ---------- Domain list parsing (file upload or textarea) ---------- */
function parseDomainList(text) {
    const entries = [];
    const seen = new Set();
    for (const line of text.split(/\r?\n/)) {
        let parts = line.split(/[,\t;]+/).map(s => s.trim().replace(/^"|"$/g, '')).filter(Boolean);
        if (!parts.length) continue;
        if (parts.length === 1) parts = parts[0].split(/\s+/).map(s => s.trim()).filter(Boolean);
        let tenant = parts.length > 1 ? parts.slice(0, -1).join(' ') : '';
        let domain = parts[parts.length - 1]
            .replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
        if (!domain.includes('.') || /^(domain|website|url|tenant|client|name)$/i.test(domain)) continue;
        if (seen.has(domain)) continue;
        seen.add(domain);
        entries.push({ tenant, domain });
    }
    return entries;
}

async function uploadDomainFile() {
    const input = document.getElementById('bulkFile');
    if (!input.files.length) return;
    try {
        const text = await input.files[0].text();
        const entries = parseDomainList(text);
        if (!entries.length) return alert('No valid domains found in file');
        document.getElementById('bulkIn').value =
            entries.map(e => e.tenant ? `${e.tenant}, ${e.domain}` : e.domain).join('\n');
        document.getElementById('bulkFileInfo').innerText =
            `${entries.length} domain(s) loaded from ${input.files[0].name}`;
    } catch (e) {
        alert('Could not read file: ' + e.message);
    }
}

/* ---------- Bulk audit ---------- */
async function auditAll() {
    const entries = parseDomainList(document.getElementById('bulkIn').value);
    if (!entries.length) return alert('Please enter or upload at least one domain');

    const btn = document.getElementById('bulkBtn');
    btn.disabled = true; btn.textContent = 'Auditing...';
    window.bulkData = [];
    document.getElementById('bulkResults').style.display = 'none';
    document.getElementById('detailSection').style.display = 'none';
    document.getElementById('bulkProgress').style.display = 'block';
    document.getElementById('bulkBar').style.width = '0%';

    const BATCH = 3;
    for (let i = 0; i < entries.length; i += BATCH) {
        const batch = await Promise.all(entries.slice(i, i + BATCH).map(e =>
            auditDomain(e.domain).then(d => { d.tenant = e.tenant; return d; })));
        window.bulkData.push(...batch);
        const pct = Math.round(window.bulkData.length / entries.length * 100);
        document.getElementById('bulkBar').style.width = pct + '%';
        document.getElementById('bulkProgressText').innerText =
            `Audited ${window.bulkData.length} of ${entries.length} domains (${pct}%)`;
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
        case 'tenant': return (d.tenant || '').toLowerCase();
        case 'domain': return d.domain;
        case 'provider': return d.provider;
        case 'dns_host': return (d.dns_host || '').toLowerCase();
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
    else { bulkSortKey = key; bulkSortDir = ['domain', 'provider', 'tenant', 'dns_host'].includes(key) ? 1 : -1; }
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
            <td>${d.tenant ? escapeHtml(d.tenant) : '<span style="color:var(--muted)">—</span>'}</td>
            <td><b>${d.domain}</b></td>
            <td>${d.provider}</td>
            <td>${escapeHtml(d.dns_host)}</td>
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

/* ---------- CSV / JSON exports ---------- */
function downloadFile(name, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
}

function exportBulkCSV() {
    if (!window.bulkData || !window.bulkData.length) return alert('No bulk data to export');
    const header = 'Tenant,Domain,Provider,DNS Host,Nameservers,SPF Valid,SPF Record,SPF Warnings,DKIM Selectors,DKIM For Provider,DMARC Policy,DMARC Report To,Score,Status\n';
    const esc = v => `"${String(v).replace(/"/g, '""')}"`;
    const rows = window.bulkData.map(d => [
        d.tenant || '', d.domain, d.provider, d.dns_host, d.ns.join('; '), d.spf.valid, d.spf.record, d.spf.warnings.join('; '),
        d.dkim_selectors.join('; '), d.score.provider_dkim, d.policy, d.report_to,
        d.score.total, d.score.status
    ].map(esc).join(','));
    downloadFile('email_security_bulk_report.csv', header + rows.join('\n'), 'text/csv');
}

function exportBulkJSON() {
    if (!window.bulkData || !window.bulkData.length) return alert('No bulk data to export');
    downloadFile('email_security_bulk_report.json', JSON.stringify(window.bulkData, null, 2), 'application/json');
}

/* ---------- Client report (HTML, print-ready) ---------- */
const REPORT_CSS = `
body{font-family:'Inter','Segoe UI',Arial,sans-serif;background:#f5f7fa;color:#1a2332;margin:0;padding:24px}
.rp{background:#fff;max-width:820px;margin:0 auto 24px;padding:40px 44px;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.08);page-break-after:always}
.rp:last-child{page-break-after:auto}
.rp-head{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #4f46e5;padding-bottom:16px;margin-bottom:24px}
.rp-head h1{font-size:22px;margin:0;color:#111827}
.rp-head p{margin:4px 0 0;color:#6b7280;font-size:14px}
.rp-date{color:#6b7280;font-size:13px;white-space:nowrap}
.rp-hero{display:flex;gap:24px;align-items:center;margin-bottom:28px;flex-wrap:wrap}
.rp-score{flex-shrink:0;text-align:center;border:2px solid #e5e7eb;border-radius:12px;padding:16px 22px}
.rp-score .num{font-size:36px;font-weight:800}
.rp-score .num small{font-size:14px;color:#9ca3af;font-weight:600}
.rp-badge{display:inline-block;margin-top:8px;padding:4px 14px;border-radius:99px;font-size:12px;font-weight:700;color:#fff;background:var(--c)}
.rp-facts{flex:1;min-width:300px;border-collapse:collapse;font-size:14px}
.rp-facts th{text-align:left;color:#6b7280;font-weight:600;padding:5px 16px 5px 0;white-space:nowrap;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.rp-facts td{padding:5px 0;color:#111827;font-weight:600}
h2{font-size:15px;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:8px;margin:26px 0 14px}
h3{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;margin:16px 0 6px}
.rp-rec{font-size:13.5px;line-height:1.8;color:#374151}
.rp-table{width:100%;border-collapse:collapse;font-size:13px}
.rp-break td{padding:7px 0;border-bottom:1px solid #f1f2f4}
.rp-break td:first-child{width:220px;font-weight:600;color:#374151}
.rp-break .barcell{padding:7px 14px}
.rp-break .bar{height:10px;background:linear-gradient(90deg,#6366f1,#22d3ee);border-radius:99px;min-width:2px}
.rp-break .pts{text-align:right;width:70px;font-weight:700;color:#111827}
pre{background:#0f172a;color:#7dd3a0;padding:14px 16px;border-radius:8px;font-size:11.5px;font-family:'JetBrains Mono',Consolas,monospace;white-space:pre-wrap;word-break:break-all;margin:0 0 6px}
.rp-foot{margin-top:28px;padding-top:14px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;text-align:center}
.text-danger{color:#b42318}.text-warning{color:#93620a}.text-success{color:#067647}.text-info{color:#1447ab}
@media print{body{background:#fff;padding:0}.rp{box-shadow:none;border-radius:0;margin:0;padding:20px 0}}
`;

function reportBodyHTML(d) {
    const color = STATUS_COLOR[d.score.status];
    const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    const facts = [
        ['Email Platform', d.provider],
        ['DNS Host (NS)', d.dns_host],
        ['DMARC Policy', d.policy],
        ['Aggregate Reports (rua)', d.report_to],
        ['SPF Record', d.spf.valid ? 'Present' : 'Missing'],
        ['DKIM Selectors', d.dkim_selectors.length ? d.dkim_selectors.join(', ') : 'None found'],
        ['Mail Exchangers (MX)', d.mx.join(', ')]
    ].map(r => `<tr><th>${r[0]}</th><td>${escapeHtml(r[1])}</td></tr>`).join('');
    const breakdown = d.score.breakdown.map(([k, v, max]) =>
        `<tr><td>${k}</td><td class="barcell"><div class="bar" style="width:${v / max * 100}%"></div></td><td class="pts">${v} / ${max}</td></tr>`).join('');
    const records = [
        ['Nameservers', d.ns.length ? d.ns.join('\n') : ''],
        ['SPF', d.spf.record],
        ['DKIM', d.dkim.join('\n')],
        ['DMARC', d.dmarc.record],
        ['CNAME', d.cname.join('\n')]
    ].filter(([, v]) => v && !v.startsWith('No '))
        .map(([t, v]) => `<h3>${t} Record${t === 'CNAME' ? 's' : ''}</h3><pre>${escapeHtml(v)}</pre>`).join('');
    return `<div class="rp">
        <div class="rp-head">
            <div><h1>Email Security Audit</h1><p>${d.tenant ? escapeHtml(d.tenant) + ' — ' : ''}${d.domain}</p></div>
            <span class="rp-date">${date}</span>
        </div>
        <div class="rp-hero">
            <div class="rp-score">
                <div class="num" style="color:${color}">${d.score.total}<small>/100</small></div>
                <span class="rp-badge" style="--c:${color}">${d.score.status}</span>
            </div>
            <table class="rp-facts">${facts}</table>
        </div>
        <h2>Executive Summary &amp; Recommendations</h2>
        <div class="rp-rec">${buildRecommendation(d)}</div>
        <h2>Score Breakdown</h2>
        <table class="rp-table rp-break">${breakdown}</table>
        <h2>DNS Records</h2>
        ${records}
        <div class="rp-foot">Generated by Email Security Auditor · All data retrieved live via DNS-over-HTTPS</div>
    </div>`;
}

function reportDocument(bodyInner) {
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Email Security Audit Report</title><style>${REPORT_CSS}</style></head><body>${bodyInner}</body></html>`;
}

function exportReport() {
    const d = window.auditData;
    if (!d) return alert('No audit loaded');
    downloadFile(`${d.domain}_audit_report.html`, reportDocument(reportBodyHTML(d)), 'text/html');
}

function exportAllReports() {
    if (!window.bulkData || !window.bulkData.length) return alert('No bulk data to export');
    downloadFile('email_security_client_reports.html',
        reportDocument(window.bulkData.map(reportBodyHTML).join('')), 'text/html');
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
                <div class="domain-name">${data.tenant ? data.tenant + ' — ' : ''}${data.domain} &nbsp;${statusBadge(data.score.status)}</div>
                <div class="stat-grid">
                    <div class="stat"><b>Email Host</b><span>${data.provider}</span></div>
                    <div class="stat"><b>DNS Host</b><span>${data.dns_host}</span></div>
                    <div class="stat"><b>DMARC Policy</b><span>${data.policy}</span></div>
                    <div class="stat"><b>Reports To</b><span>${data.report_to}</span></div>
                    <div class="stat"><b>SPF</b><span>${data.spf.valid ? 'Found' : 'Missing'}</span></div>
                    <div class="stat"><b>DKIM</b><span>${data.dkim_selectors.length ? data.dkim_selectors.length + ' selector(s)' : 'None'}</span></div>
                </div>
            </div>
        </div>`;

    const rec = buildRecommendation(data);
    document.getElementById('printDate').innerText = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    document.getElementById('printRec').innerHTML = '<h5><b>Executive Summary</b></h5>' + rec;
    document.getElementById('recText').innerHTML = rec;
    document.getElementById('nsRec').innerText = data.ns.length ? data.ns.join('\n') : 'No nameservers found';
    document.getElementById('mxRec').innerText = data.mx.join('\n');
    document.getElementById('spfRec').innerText = data.spf.record;
    document.getElementById('spfWarnings').innerHTML = data.spf.warnings.length > 0
        ? "<small class='text-warning'>⚠️ " + data.spf.warnings.join('<br>⚠️ ') + '</small>'
        : '';
    document.getElementById('dmarcRec').innerText = data.dmarc.record;
    document.getElementById('dkimRec').innerText = data.dkim.join('\n');
    document.getElementById('cnameRec').innerText = data.cname.join('\n');

    // Prefill DMARC fixer email from existing rua if present, reset output
    const emailBox = document.getElementById('dmarcEmail');
    if (emailBox) emailBox.value = (data.report_to && data.report_to !== 'Not Configured') ? data.report_to : '';
    const out = document.getElementById('dmarcFixOut');
    if (out) out.style.display = 'none';
}

/* ---------- DMARC Fixer ---------- */
function dmarcNextStep(policy) {
    switch (policy) {
        case 'Missing':
            return { p: 'none', stage: 'Not set up → Step 1: Monitoring (report only, no mail blocked)',
                note: "Add this TXT record and leave it for 1–2 weeks. No legitimate email is blocked — it just tells you who is sending mail for you. Review the emailed reports, then come back and generate the Quarantine step." };
        case 'None':
            return { p: 'quarantine', stage: 'On report-only → Step 2: Quarantine (suspicious mail sent to spam)',
                note: "Your SPF/DKIM must be correct first, or legitimate mail could be quarantined. Use the Gradual rollout option (e.g. 25%) to start, confirm no issues in reports, then move to 100%. When stable, come back and generate the Reject (block) step." };
        case 'Quarantine':
            return { p: 'reject', stage: 'Report + Quarantine → Step 3: Reject (block spoofing)',
                note: "This is full enforcement — unauthorised mail is rejected outright. Confirm your DMARC reports show all legitimate senders passing SPF or DKIM before switching, to avoid blocking genuine mail (e.g. parent comms, MIS/banking)." };
        case 'Reject':
            return { p: 'reject', stage: 'Already at full enforcement (Reject) — optimal',
                note: "You are already on the strongest policy. This record keeps reporting to your chosen email. No further step needed." };
        default:
            return { p: 'none', stage: 'Monitoring', note: '' };
    }
}

function buildDmarc() {
    const data = window.auditData;
    if (!data) return alert('Run an audit first');
    let email = document.getElementById('dmarcEmail').value.trim();
    if (!email) return alert('Enter the email address that should receive DMARC reports');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return alert('That does not look like a valid email address');

    const step = dmarcNextStep(data.policy);
    const pct = parseInt(document.getElementById('dmarcPct').value, 10);
    let rec = `v=DMARC1; p=${step.p};`;
    if (step.p !== 'none' && pct < 100) rec += ` pct=${pct};`;
    rec += ` rua=mailto:${email}`;

    document.getElementById('dmarcHost').innerText = `_dmarc.${data.domain}`;
    document.getElementById('dmarcValue').innerText = rec;
    document.getElementById('dmarcFixStage').innerText = step.stage;
    document.getElementById('dmarcFixNote').innerText = step.note;
    document.getElementById('dmarcFixOut').style.display = 'block';
    window._dmarcRec = rec;
}

function copyDmarc() {
    const text = window._dmarcRec;
    if (!text) return;
    const done = () => {
        const btns = document.querySelectorAll('#dmarcFixOut .btn');
        if (btns.length) { btns[0].textContent = 'Copied ✓'; setTimeout(() => btns[0].textContent = 'Copy', 1500); }
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    } else {
        fallbackCopy(text, done);
    }
}

function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    if (done) done();
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
    downloadFile(window.auditData.domain + '_audit.json', JSON.stringify(window.auditData, null, 2), 'application/json');
}

function exportCSV() {
    if (!window.auditData) return alert('No audit data to export');
    const d = window.auditData;
    let csv = 'Field,Value\n';
    if (d.tenant) csv += `Tenant,${d.tenant}\n`;
    csv += `Domain,${d.domain}\n`;
    csv += `Email Provider,${d.provider}\n`;
    csv += `DNS Host,${d.dns_host}\n`;
    csv += `Nameservers,"${d.ns.join('; ')}"\n`;
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
    downloadFile(d.domain + '_audit.csv', csv, 'text/csv');
}
