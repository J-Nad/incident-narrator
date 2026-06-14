const SCENARIOS = [
  {tag:"Web scanning attack", text:"Investigate suspicious web scanning activity from external IP 45.7.231.174 generating 84 HTTP error responses across multiple sites in the botsv3 dataset. Determine if this is reconnaissance, exploitation attempts, or vulnerability scanning. Identify targeted sites, attack patterns, and whether any exploitation was successful."},
  {tag:"Suspicious IP activity", text:"Investigate IP address 61.75.35.114 responsible for 56 HTTP errors in botsv3. Correlate this IP across web traffic (stream:http), DNS queries (stream:dns), and network flows to determine if this is malicious activity or a misconfigured service. Assess threat level and scope."},
  {tag:"DNS analysis", text:"Investigate DNS query patterns in botsv3 stream:dns data. Look for anomalous queries, possible C2 communication, DNS tunneling, or connections to suspicious domains. Correlate high-volume query sources with web traffic and network flows."},
  {tag:"Network exfiltration", text:"Investigate potential data exfiltration in botsv3. Analyze stream:ip and stream:tcp for large outbound data transfers, unusual destination IPs, or sustained connections. Correlate with DNS to identify external destinations and source hosts."},
];

let HEALTH = null;
let CURRENT = null;

function $(s){ return document.querySelector(s); }
function el(tag, cls, html){ const e=document.createElement(tag); if(cls)e.className=cls; if(html!=null)e.innerHTML=html; return e; }
function esc(t){ const d=document.createElement('div'); d.textContent=(t==null?'':String(t)); return d.innerHTML; }
function ago(ts){
  const s=Math.floor(Date.now()/1000-ts);
  if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago';
}
function fmtMs(ms){ return ms>=1000?(ms/1000).toFixed(1)+'s':ms+'ms'; }

function go(view){
  document.querySelectorAll('.nav-link').forEach(b=>b.classList.toggle('active', b.dataset.view===view));
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active', v.id==='view-'+view));
  if(view==='dashboard') loadDashboard();
  if(view==='history') loadHistory();
  if(view==='connections') loadConnections();
}

async function loadHealth(){
  try{ HEALTH = await (await fetch('/api/health')).json(); }catch(e){ HEALTH={}; }
  setDot('dotMcp', HEALTH.mcp);
  setDot('dotGem', HEALTH.gemini);
}
function setDot(id, up){ const d=$('#'+id); if(d){ d.classList.remove('up','down'); d.classList.add(up?'up':'down'); } }

async function loadDashboard(){
  let s={};
  try{ s = await (await fetch('/api/stats')).json(); }catch(e){}
  $('#kpiTotal').textContent = s.total||0;
  $('#kpiConfirmed').textContent = s.confirmed||0;
  $('#kpiCrit').textContent = s.critical_high||0;
  $('#kpiAvg').textContent = s.avg_duration_ms?fmtMs(s.avg_duration_ms):'—';

  let list=[];
  try{ list = await (await fetch('/api/investigations')).json(); }catch(e){}
  const wrap=$('#recentWrap');
  if(!list.length){
    wrap.innerHTML='<div class="empty"><div class="big">No investigations yet</div>Run your first investigation to populate the dashboard.</div>';
    return;
  }
  wrap.innerHTML='';
  const tbl=el('table','list-table');
  tbl.innerHTML='<thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Source</th><th>When</th></tr></thead>';
  const tb=el('tbody');
  list.slice(0,8).forEach(i=>tb.appendChild(rowFor(i)));
  tbl.appendChild(tb); wrap.appendChild(tbl);
}

function rowFor(i){
  const tr=el('tr');
  tr.innerHTML=`<td><div class="list-title">${esc(i.title||'Untitled')}</div><div class="list-alert">${esc(i.alert)}</div></td>
    <td><span class="sev ${i.severity||'info'}">${esc(i.severity||'info')}</span></td>
    <td><span class="statustag ${i.status||''}">${esc((i.status||'').replace(/_/g,' '))}</span></td>
    <td><b>${i.confidence||0}%</b></td>
    <td class="ago">${esc(i.via||'')}</td>
    <td class="ago">${ago(i.created_at)}</td>`;
  tr.onclick=()=>openInvestigation(i.id);
  return tr;
}

async function loadHistory(){
  let list=[];
  try{ list = await (await fetch('/api/investigations')).json(); }catch(e){}
  const wrap=$('#historyWrap');
  if(!list.length){ wrap.innerHTML='<div class="card card-pad empty"><div class="big">No investigations yet</div>Start one from the New Investigation tab.</div>'; return; }
  const card=el('div','card');
  const tbl=el('table','list-table');
  tbl.innerHTML='<thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Source</th><th>When</th></tr></thead>';
  const tb=el('tbody'); list.forEach(i=>tb.appendChild(rowFor(i)));
  tbl.appendChild(tb); card.appendChild(tbl); wrap.innerHTML=''; wrap.appendChild(card);
}

async function openInvestigation(id){
  go('detail');
  $('#detailWrap').innerHTML='<div class="spinner"></div><div class="loadnote">Loading investigation…</div>';
  try{
    const d = await (await fetch('/api/investigations/'+id)).json();
    CURRENT = d.report;
    renderDetail(d.trace, d.report, d.duration_ms, id);
  }catch(e){ $('#detailWrap').innerHTML='<div class="empty">Could not load investigation.</div>'; }
}

function renderScenarios(){
  $('#scenarios').innerHTML = SCENARIOS.map((s,i)=>
    `<button class="scenario" onclick="pick(${i})"><div class="tag">${esc(s.tag)}</div><div class="desc">${esc(s.text)}</div></button>`).join('');
}
function pick(i){ $('#alertInput').value = SCENARIOS[i].text; $('#alertInput').focus(); }

async function runInvestigation(){
  const alert = $('#alertInput').value.trim();
  if(!alert){ $('#alertInput').focus(); return; }
  const btn=$('#runBtn'); btn.disabled=true; btn.textContent='Investigating…';
  $('#liveArea').classList.remove('hidden');
  $('#traceList').innerHTML='';
  $('#reportArea').innerHTML='';
  $('#traceLabel').innerHTML='<span class="pulse"></span> Investigation in progress';

  try{
    const d = await (await fetch('/api/investigate',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({alert})})).json();
    if(d.error){ $('#reportArea').innerHTML=`<div class="card card-pad terr">Error: ${esc(d.error)}</div>`; resetBtn(); return; }

    const list=$('#traceList');
    for(const s of d.trace){ await sleep(160); list.appendChild(traceNode(s)); }
    $('#traceLabel').textContent='Investigation complete';
    await sleep(300);
    CURRENT=d.report;
    $('#reportArea').appendChild(reportCard(d.trace, d.report, d.duration_ms, d.id));
    $('#reportArea').scrollIntoView({behavior:'smooth',block:'start'});
  }catch(e){ $('#reportArea').innerHTML=`<div class="card card-pad terr">${esc(e.message)}</div>`; }
  resetBtn();
}
function resetBtn(){ const b=$('#runBtn'); b.disabled=false; b.textContent='Run investigation'; }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

function traceNode(s){
  const n=el('div','tnode');
  let via='';
  if(s.ok===true) via=`<span class="via ${s.via==='mcp'?'mcp':'rest'}">${esc((s.via||'').toUpperCase())}</span>`;
  else if(s.ok===false) via=`<span class="via err">TOOL ERROR</span>`;
  let h=`<div class="tnode-top"><span class="stepn">STEP ${s.step}</span><span class="taction">${esc(s.action||s.type||'')}</span>${via}</div>`;
  if(s.thinking) h+=`<div class="treason">${esc(s.thinking)}</div>`;
  if(s.query) h+=`<div class="tspl">${esc(s.query)}</div>`;
  if(s.ok===true && typeof s.result_count!=='undefined') h+=`<div class="tmeta">↳ ${s.result_count} result(s) via ${esc((s.via||'').toUpperCase())}</div>`;
  if(s.ok===false) h+=`<div class="terr"><b>TOOL ERROR (${esc(s.error_kind)}):</b> ${esc(s.tool_error)} — treated as a tooling problem, not evidence.</div>`;
  if(s.summary) h+=`<div class="tconc">✓ ${esc(s.summary)}</div>`;
  if(s.reason) h+=`<div class="terr"><b>Halted:</b> ${esc(s.reason)}</div>`;
  n.innerHTML=h; return n;
}

function renderDetail(trace, report, duration, id){
  CURRENT=report;
  const wrap=$('#detailWrap'); wrap.innerHTML='';
  const tl=el('div'); tl.className='section-title'; tl.textContent='Investigation trace';
  const traceList=el('div','trace');
  (trace||[]).forEach(s=>traceList.appendChild(traceNode(s)));
  wrap.appendChild(tl); wrap.appendChild(traceList);
  wrap.appendChild(reportCard(trace, report, duration, id));
}

function reportCard(trace, r, duration, id){
  const sev=(r.severity||'info').toLowerCase();
  const status=(r.status||'').toLowerCase();
  const conf=r.confidence||0;
  const card=el('div','card report');
  let h=`<div class="rhead">
    <div class="badges"><span class="sev ${sev}">${esc(r.severity||'info')}</span>
      <span class="statustag ${status}">${esc((r.status||'').replace(/_/g,' '))}</span></div>
    <h2>${esc(r.title||'Incident report')}</h2>
    <div class="confidence"><div class="conf-row">
      <div class="conf-bar"><div class="conf-fill" style="width:${conf}%;background:${conf>=70?'var(--low)':conf>=40?'var(--med)':'var(--high)'}"></div></div>
      <div class="conf-num">${conf}%</div></div>
      ${r.confidence_rationale?`<div class="conf-rationale">${esc(r.confidence_rationale)}</div>`:''}
    </div></div><div class="rbody">`;

  if(r.executive_summary) h+=blk('Executive summary',`<p>${esc(r.executive_summary)}</p>`);
  if(r.attack_narrative) h+=blk('Attack narrative',`<div class="narr">${esc(r.attack_narrative)}</div>`);
  if(r.timeline&&r.timeline.length) h+=blk('Timeline', r.timeline.map(t=>`<div class="tl"><span class="t">${esc(t.time)}</span><span>${esc(t.event)}</span></div>`).join(''));
  if(r.indicators_of_compromise&&r.indicators_of_compromise.length) h+=blk('Indicators of compromise', r.indicators_of_compromise.map(i=>`<div class="ioc"><span class="type">${esc(i.type)}</span><span class="val">${esc(i.value)}</span><span class="ctx">${esc(i.context||'')}</span></div>`).join(''));
  if(r.mitre_attack&&r.mitre_attack.length) h+=blk('MITRE ATT&CK', `<table class="tbl"><tr><th>Tactic</th><th>Technique</th><th>Evidence</th></tr>${r.mitre_attack.map(m=>`<tr><td>${esc(m.tactic)}</td><td class="tech">${esc(m.technique)}</td><td>${esc(m.evidence||'')}</td></tr>`).join('')}</table>`);
  if(r.affected_assets&&r.affected_assets.length) h+=blk('Affected assets', `<table class="tbl"><tr><th>Asset</th><th>Impact</th></tr>${r.affected_assets.map(a=>`<tr><td class="tech">${esc(a.asset)}</td><td>${esc(a.impact)}</td></tr>`).join('')}</table>`);
  if(r.root_cause) h+=blk('Root cause',`<p>${esc(r.root_cause)}</p>`);
  if(r.recommended_actions&&r.recommended_actions.length) h+=blk('Recommended actions', r.recommended_actions.map(a=>`<div class="act"><span class="pri ${esc(a.priority)}">${esc(a.priority)}</span><span>${esc(a.action)}</span><span class="owner">${esc(a.owner||'')}</span></div>`).join(''));
  if(r.evidence_queries&&r.evidence_queries.length) h+=blk('Evidence queries', `<ul class="qlist">${r.evidence_queries.map(q=>`<li>${esc(q)}</li>`).join('')}</ul>`);
  h+=`</div>`;

  const m=r._meta||{};
  h+=`<div class="rfoot"><span>Splunk access: <b>${m.mcp_used?'MCP Server':'REST fallback'}</b></span>
    <span>Data pulls: <b>${m.data_pulls||0}</b></span>
    <span>Tool failures: <b>${m.tool_failures||0}</b></span>
    <span>Queries: <b>${(m.queries_run||[]).length}</b></span>
    ${duration?`<span>Time: <b>${fmtMs(duration)}</b></span>`:''}</div>
    <div class="rtools"><button class="btn btn-ghost btn-sm" onclick="exportMd()">Export Markdown</button>
    <button class="btn btn-ghost btn-sm" onclick="copyJson()">Copy JSON</button></div>`;
  card.innerHTML=h;
  return card;
}
function blk(title, inner){ return `<div class="rblock"><h3>${title}</h3>${inner}</div>`; }

function exportMd(){
  const r=CURRENT; if(!r)return;
  let m=`# ${r.title}\n\n**Severity:** ${r.severity}  **Status:** ${r.status}  **Confidence:** ${r.confidence}%\n\n`;
  if(r.confidence_rationale) m+=`> ${r.confidence_rationale}\n\n`;
  m+=`## Executive Summary\n${r.executive_summary||''}\n\n## Attack Narrative\n${r.attack_narrative||''}\n\n`;
  if(r.timeline) m+=`## Timeline\n`+r.timeline.map(t=>`- **${t.time}** — ${t.event}`).join('\n')+`\n\n`;
  if(r.indicators_of_compromise) m+=`## Indicators of Compromise\n`+r.indicators_of_compromise.map(i=>`- \`${i.value}\` (${i.type}) — ${i.context||''}`).join('\n')+`\n\n`;
  if(r.mitre_attack) m+=`## MITRE ATT&CK\n`+r.mitre_attack.map(x=>`- **${x.tactic}** / ${x.technique} — ${x.evidence||''}`).join('\n')+`\n\n`;
  if(r.root_cause) m+=`## Root Cause\n${r.root_cause}\n\n`;
  if(r.recommended_actions) m+=`## Recommended Actions\n`+r.recommended_actions.map(a=>`- [${a.priority}] ${a.action} (${a.owner||''})`).join('\n')+`\n\n`;
  if(r.evidence_queries) m+=`## Evidence Queries\n`+r.evidence_queries.map(q=>'```\n'+q+'\n```').join('\n');
  const a=el('a'); a.href=URL.createObjectURL(new Blob([m],{type:'text/markdown'}));
  a.download='incident_report.md'; a.click();
}
function copyJson(){ navigator.clipboard.writeText(JSON.stringify(CURRENT,null,2)); const b=event.target; const t=b.textContent; b.textContent='Copied'; setTimeout(()=>b.textContent=t,1200); }

async function loadConnections(){
  await loadHealth();
  const h=HEALTH||{};
  const cards=[
    {title:'Splunk MCP Server', up:h.mcp, desc:'Primary integration. The agent calls splunk_run_query, splunk_get_indexes, splunk_get_metadata and the AI Assistant tool saia_generate_spl over JSON-RPC.', meta:h.host},
    {title:'Splunk REST API', up:h.rest, desc:'Automatic fallback. If the MCP Server is unreachable, searches run through /services/search/jobs so investigations still complete.', meta:h.host},
    {title:'Google Gemini', up:h.gemini, desc:'Reasoning engine driving the investigation loop and report synthesis.', meta:'gemini-2.5-flash'},
    {title:'Dataset', up:h.index_status==='available', desc:'Splunk Boss of the SOC v3 — realistic enterprise security telemetry the agent investigates.', meta:'index = '+(h.index||'botsv3')+(h.index_status?(' · '+h.index_status):'')},
  ];
  $('#connWrap').innerHTML = cards.map(c=>`
    <div class="conn-card"><div class="ctitle"><h4>${esc(c.title)}</h4>
      <span class="statebadge ${c.up?'up':'down'}">${c.up?'Connected':'Offline'}</span></div>
      <div class="cdesc">${esc(c.desc)}</div>
      <div class="cmeta">${esc(c.meta||'')}</div></div>`).join('');
}

renderScenarios();
loadHealth();
go('dashboard');
setInterval(loadHealth, 30000);
