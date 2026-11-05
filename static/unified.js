/* EXE-SOC "Telemetry" page: SOC overview, unified event explorer, collector health, detection rules, alert evidence + correlation timeline.
   All event content is untrusted: every value goes through esc() (never innerHTML raw); raw events are shown with textContent. Loaded after fleet.js, before app.js. */
(function(){
window.SOCX_PAGES=window.SOCX_PAGES||{};
let tab='overview',off=0,LIM=50,timer=null;
const SEV={Critical:'s-critical',High:'s-high',Medium:'s-medium',Low:'s-low'};
const bar=(rows,k='k')=>{const m=Math.max(1,...rows.map(r=>r.n));return rows.map(r=>`<div style="display:flex;gap:8px;align-items:center;margin:3px 0"><span style="width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r[k]??r.source+' '+r.k)}</span><span style="flex:1;background:var(--line,#2a3342);height:8px;border-radius:4px"><i style="display:block;height:8px;border-radius:4px;background:var(--accent,#4da3ff);width:${Math.round(r.n*100/m)}%"></i></span><b>${esc(r.n)}</b></div>`).join('')||'<small>no data</small>'};
const dur=s=>s==null?'n/a':s<90?s+' s':s<5400?Math.round(s/60)+' min':s<172800?Math.round(s/3600)+' h':Math.round(s/86400)+' d';
function tabs(){return `<div class="bar" style="margin-bottom:12px;gap:6px">${[['overview','Overview'],['events','Event explorer'],['health','Collector health'],['rules','Detection rules']].map(([k,l])=>`<button class="btn mini ${tab===k?'':'ghost'}" data-t="${k}">${l}</button>`).join('')}</div><div id="u_body"></div>`}
function shell(){P().innerHTML=tabs();P().querySelectorAll('[data-t]').forEach(b=>b.onclick=()=>{tab=b.dataset.t;off=0;shell();go()})}
async function overview(){
  const o=await api('/api/u/overview?hours=24');
  $('#u_body').innerHTML=`<div class="bar"><b>${esc(o.events)}</b> events (24 h) · <b>${esc(o.hosts_reporting)}</b> hosts reporting / ${esc(o.endpoints)} registered</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin-top:10px">
  <div class="card"><h3>Events by source</h3>${bar(o.by_source)}</div><div class="card"><h3>Top event IDs</h3>${bar(o.by_event_id)}</div>
  <div class="card"><h3>Authentication</h3>${bar(o.auth)}</div><div class="card"><h3>Top hosts</h3>${bar(o.top_hosts)}</div>
  <div class="card"><h3>Detections by severity</h3>${bar(o.alerts_by_severity)}</div><div class="card"><h3>Events per hour (UTC)</h3>${bar(o.over_time.slice(-12).map(r=>({k:r.h.replace('T',' ')+':00',n:r.n})))}</div></div>
  <h3 style="margin:16px 0 8px">Recent rule-based detections</h3><table class="tbl"><thead><tr><th>Time</th><th>Sev</th><th>Rule</th><th>Detection</th><th>Host</th><th>Account</th><th>Conf.</th><th>Status</th></tr></thead><tbody>
  ${o.recent.map(a=>`<tr class="clickable" data-a="${esc(a.id)}"><td>${esc(a.ts)}</td><td><span class="pill ${SEV[a.severity]||''}">${esc(a.severity)}</span></td><td>${esc(a.rule_id)}</td><td>${esc(a.title)}</td><td>${esc(a.host)}</td><td>${esc(a.account||'')}</td><td>${esc(a.confidence)}</td><td>${esc(a.status)}</td></tr>`).join('')||'<tr><td colspan="8">No rule-based detections yet.</td></tr>'}</tbody></table><div id="u_ev"></div>`;
  $$('#u_body tr[data-a]').forEach(r=>r.onclick=()=>alertEvidence(r.dataset.a));
}
async function alertEvidence(id){
  const d=await api('/api/u/alerts/'+id),box=$('#u_ev');
  const st=can('analyst')?`<select id="u_st">${['New','Investigating','Confirmed','False Positive','Resolved'].map(s=>`<option ${s===d.alert.status?'selected':''}>${s}</option>`).join('')}</select> <input id="u_note" placeholder="analyst note" maxlength="500"> <button class="btn mini" id="u_save">Save status</button> <button class="btn mini ghost" id="u_tl">Correlation timeline</button>`:'';
  box.innerHTML=`<div class="card" style="margin-top:14px"><h3>#${esc(id)} ${esc(d.alert.title)} <small>rule ${esc(d.rule.id)} v${esc(d.rule.version)} · confidence ${esc(d.rule.confidence)}</small></h3>
  <p>${esc(d.summary)}</p><p><b>Host</b> ${esc(d.host)} · <b>Account</b> ${esc(d.account||'n/a')} · <b>First/last seen</b> ${esc(d.first_seen)} → ${esc(d.last_seen)} · <b>Event IDs</b> ${esc((d.event_ids||[]).join(', '))} · <b>MITRE</b> ${esc(d.rule.mitre||'n/a')}</p>
  <p><b>Investigate:</b></p><ol>${d.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol><p><b>False-positive considerations:</b> ${esc(d.false_positive_considerations)}</p><div class="bar">${st}</div>
  <p><b>Status history</b></p><ul>${d.history.map(h=>`<li>${esc(h.ts)} ${esc(h.user)}: ${esc(h.old_status)} → ${esc(h.new_status)} ${esc(h.note||'')}</li>`).join('')||'<li>none</li>'}</ul>
  <p><b>Supporting events (${d.evidence_ids.length})</b></p>${evTable(d.evidence)}<div id="u_tlbox"></div></div>`;
  bindRows(box);
  if(can('analyst')){$('#u_save').onclick=async()=>{await api('/api/u/alerts/'+id+'/status','POST',{status:$('#u_st').value,note:$('#u_note').value});toast('Status updated');alertEvidence(id)};
    $('#u_tl').onclick=async()=>{const t=await api('/api/u/alerts/'+id+'/timeline');$('#u_tlbox').innerHTML=`<h4>Correlation timeline <small>confidence ${esc(t.confidence)} · ${esc(t.summary)}</small></h4><p><small>${esc(t.note)}</small></p><table class="tbl"><tbody>${t.nodes.map(n=>`<tr><td>${esc(n.timestamp)}</td><td>${esc(n.source)} ${esc(n.event_id??'')}</td><td>${esc(n.activity||'')}</td><td>${esc(n.process_name||n.dns_query_name||n.target_filename||n.target_username||'')}</td><td>${esc(n.destination_ip||n.source_ip||'')}</td></tr>`).join('')}</tbody></table><h4>Why linked</h4><ul>${t.links.map(l=>`<li><b>${esc(l.basis)}</b> (${esc(l.confidence)}): #${esc(l.from)} → #${esc(l.to)} — ${esc(l.reason)}</li>`).join('')}</ul>`}}
  box.scrollIntoView({behavior:'smooth'});
}
const evTable=rows=>`<table class="tbl"><thead><tr><th>Time (UTC)</th><th>Host</th><th>Source</th><th>ID</th><th>User</th><th>Src → Dst</th><th>Process / detail</th><th>Rule</th></tr></thead><tbody>${rows.map(r=>`<tr class="clickable" data-e="${esc(r.id)}"><td>${esc(r.timestamp)}</td><td>${esc(r.host)}</td><td>${esc(r.source)}</td><td>${esc(r.event_id??r.activity??'')}</td><td>${esc(r.target_username||r.username||'')}</td><td>${esc(r.source_ip||'')}${r.destination_ip?' → '+esc(r.destination_ip)+':'+esc(r.destination_port??''):''}</td><td>${esc((r.process_name||'')+' '+(r.command_line||r.dns_query_name||r.target_filename||r.registry_key||r.service_name||r.task_name||r.group_name||'')).slice(0,160)}</td><td>${esc(r.rule_name||'')}</td></tr>`).join('')||'<tr><td colspan="8">No events.</td></tr>'}</tbody></table>`;
function bindRows(root){$$('tr[data-e]',root).forEach(r=>r.onclick=async()=>{if(!can('analyst')){toast('Raw events need the analyst role');return}const e=await api('/api/u/events/'+r.dataset.e);const pre=document.createElement('pre');pre.style.cssText='white-space:pre-wrap;max-height:300px;overflow:auto';pre.textContent=JSON.stringify(Object.assign({},e,{raw_event:undefined}),null,2)+'\n\n--- raw event (stored text) ---\n'+(e.raw_event||'(raw not retained)');const old=$('#u_raw');if(old)old.remove();const w=document.createElement('div');w.id='u_raw';w.className='card';w.appendChild(pre);r.closest('table').after(w)})}
const F=['host','platform','source','event_id','username','source_ip','destination_ip','process_name','rule_name','since','until','text'];
async function events(){
  const m=await api('/api/u/meta'),sel=(id,a,ph)=>`<select id="uf_${id}"><option value="">${ph}</option>${a.map(v=>`<option>${esc(v)}</option>`).join('')}</select>`;
  $('#u_body').innerHTML=`<div class="bar" style="flex-wrap:wrap;gap:6px">${sel('host',m.hosts,'host')}${sel('platform',m.platforms,'OS')}${sel('source',m.sources,'source')}${sel('event_id',m.event_ids,'event id')}
  <input id="uf_username" placeholder="user"><input id="uf_source_ip" placeholder="source IP"><input id="uf_destination_ip" placeholder="dest IP"><input id="uf_process_name" placeholder="process">
  <select id="uf_rule_name"><option value="">rule</option>${m.rules.map(r=>`<option value="${esc(r.name)}">${esc(r.id)} ${esc(r.name)}</option>`).join('')}</select>
  <input id="uf_since" placeholder="from 2024-05-01T00:00" size="18"><input id="uf_until" placeholder="to" size="18"><input id="uf_text" placeholder="text in cmd/file/dns"><button class="btn mini" id="uf_go">Search</button>${can('analyst')?'<a class="btn mini ghost" id="uf_csv">Export CSV</a>':''}</div><div id="u_res"></div>`;
  const qs=()=>F.map(k=>{const v=$('#uf_'+k).value.trim();return v?k+'='+encodeURIComponent(v):''}).filter(Boolean).join('&');
  const run=async()=>{const r=await api('/api/u/events?limit='+LIM+'&offset='+off+'&'+qs());$('#u_res').innerHTML=`<p><small>${esc(r.total)} matching events · showing ${off+1}–${Math.min(off+LIM,r.total)}</small> <button class="btn mini ghost" id="u_pv" ${off?'':'disabled'}>◀</button> <button class="btn mini ghost" id="u_nx" ${off+LIM<r.total?'':'disabled'}>▶</button></p>${evTable(r.rows)}`;bindRows($('#u_res'));$('#u_pv').onclick=()=>{off=Math.max(0,off-LIM);run()};$('#u_nx').onclick=()=>{off+=LIM;run()}};
  $('#uf_go').onclick=()=>{off=0;run()};if(can('analyst'))$('#uf_csv').onclick=()=>{location.href='/api/u/events/export.csv?'+qs()};run();
}
async function health(){
  const h=await api('/api/u/health');
  $('#u_body').innerHTML=`<p><small>${esc(h.note)}</small></p><table class="tbl"><thead><tr><th>Host</th><th>Source</th><th>Channel</th><th>Last record</th><th>Newest event</th><th>Lag</th><th>Silent for</th><th>Events</th><th>Errors</th></tr></thead><tbody>
  ${h.collectors.map(c=>`<tr><td>${esc(c.host)}</td><td>${esc(c.source)}</td><td>${esc(c.channel)}</td><td>${esc(c.last_record_id??'')}</td><td>${esc(c.last_event_ts||'')}</td><td>${dur(c.lag_s)}</td><td>${c.silent_s>600?'⚠ ':''}${dur(c.silent_s)}</td><td>${esc(c.events_total)}</td><td>${esc(c.parse_errors)} ${esc(c.last_error||'')}</td></tr>`).join('')||'<tr><td colspan="9">No collector activity yet.</td></tr>'}</tbody></table>
  <h3 style="margin:14px 0 6px">Telemetry gaps</h3><ul>${h.telemetry_gaps.map(g=>`<li><b>${esc(g.host)}</b> ${esc(g.flag)} — ${esc(g.detail)} <small>(${esc(g.hits)} events, last ${esc(g.last_seen)})</small></li>`).join('')||'<li>none detected</li>'}</ul>
  <p><b>Windows hosts without Sysmon data:</b> ${esc(h.windows_hosts_without_sysmon.join(', ')||'none')}</p>`;
}
async function rules(){
  const r=await api('/api/u/rules'),adm=can('admin');
  $('#u_body').innerHTML=`<table class="tbl"><thead><tr><th>ID</th><th>Rule</th><th>Ver</th><th>Sev</th><th>Conf.</th><th>MITRE</th><th>Parameters</th><th>On</th></tr></thead><tbody>${r.map(x=>`<tr><td>${esc(x.id)}</td><td><b>${esc(x.name)}</b><br><small>${esc(x.description)}</small><br><small><i>False positives:</i> ${esc(x.false_positives)}</small></td><td>${esc(x.version)}</td><td>${esc(x.severity)}</td><td>${esc(x.confidence)}</td><td>${esc(x.mitre)}</td>
  <td>${adm?`<input data-p="${esc(x.id)}" size="34" value="${esc(JSON.stringify(x.params))}">`:`<code>${esc(JSON.stringify(x.params))}</code>`}</td><td>${adm?`<input type="checkbox" data-en="${esc(x.id)}" ${x.enabled?'checked':''}>`:(x.enabled?'yes':'no')}</td></tr>`).join('')}</tbody></table>${adm?'<p><button class="btn mini" id="ur_save">Save changes</button></p>':''}
  ${can('analyst')?'<p><button class="btn mini ghost" id="ur_test">Run built-in rule tests</button> <span id="ur_res"></span></p>':''}`;
  if(adm)$('#ur_save').onclick=async()=>{try{for(const x of r){const p=JSON.parse($(`[data-p="${x.id}"]`).value),en=$(`[data-en="${x.id}"]`).checked;if(JSON.stringify(p)!==JSON.stringify(x.params)||en!==x.enabled)await api('/api/u/rules/'+x.id,'PATCH',{params:p,enabled:en})}toast('Saved')}catch(e){toast('Invalid value: '+e.message)}};
  if(can('analyst'))$('#ur_test').onclick=async()=>{const t=await api('/api/u/rules/selftest');$('#ur_res').textContent=`${t.passed}/${t.total} built-in positive/negative cases pass`};
}
function go(){clearInterval(timer);({overview,events,health,rules})[tab]();if(tab==='overview'||tab==='health')timer=setInterval(()=>{if(!document.hidden&&!$('#u_raw')&&!$('#u_ev .card'))go()},20000)}
window.SOCX_PAGES.telemetry={t:['Telemetry','Windows Security, Sysmon and Linux events: normalised, searchable and correlated'],load(){shell();go()}};
})();
