/* EXE-SOC "Remote agents" page: enrolled endpoints, enrollment tokens, per-endpoint details/filters. Loaded after notify.js, before app.js. */
(function(){
window.SOCX_PAGES=window.SOCX_PAGES||{};
const DOT={online:'🟢',warning:'🟡',offline:'🔴',revoked:'⛔'},CATS=['','Authentication','Process','Network','File','Privilege','User','System'],SEVS=['','Critical','High','Medium','Low','Normal'];
const ago=t=>{if(!t)return'never';const s=(Date.now()-new Date(t.replace(' ','T')))/1000;return s<90?Math.round(s)+' s ago':s<5400?Math.round(s/60)+' min ago':s<172800?Math.round(s/3600)+' h ago':Math.round(s/86400)+' d ago'};
const opts=(a,sel)=>a.map(v=>`<option value="${esc(v)}" ${v===sel?'selected':''}>${esc(v||'any')}</option>`).join('');
let timer=null,cur=null;
async function list(){
  const a=await api('/api/agents'),cnt={online:0,warning:0,offline:0,revoked:0};a.forEach(x=>cnt[x.state]=(cnt[x.state]||0)+1);
  const adm=can('admin');
  P().innerHTML=`<div class="bar" style="margin-bottom:10px"><b>${a.length} endpoint(s)</b> <span>🟢 ${cnt.online} online · 🟡 ${cnt.warning} warning · 🔴 ${cnt.offline} offline · ⛔ ${cnt.revoked} revoked</span>
   ${adm?'<button class="btn mini" id="f_add">+ Enroll endpoint</button>':''}</div>
  <table class="tbl"><thead><tr><th></th><th>Endpoint</th><th>OS</th><th>Last heartbeat</th><th>IP</th><th>Agent</th><th>Alerts</th><th>Events</th><th>Queued</th><th>CPU/RAM</th></tr></thead><tbody>
  ${a.map(x=>`<tr class="clickable" data-id="${esc(x.id)}"><td>${DOT[x.state]}</td><td><b>${esc(x.hostname)}</b><br><small>${esc(x.id)}</small></td><td>${esc(x.os)}</td><td>${ago(x.last_heartbeat)}</td><td>${esc(x.ip||'')}</td>
   <td>${esc(x.agent_version||'')}</td><td>${x.open_alerts?`<span class="pill s-high">${x.open_alerts}</span>`:0} / ${x.alert_count}</td><td>${x.event_count}</td><td>${x.health.events_queued??''}</td><td>${Math.round(x.health.cpu||0)}% / ${Math.round(x.health.mem||0)}%</td></tr>`).join('')||'<tr><td colspan="10">No remote endpoints yet. Use “Enroll endpoint”.</td></tr>'}</tbody></table>
  <p style="color:var(--muted);font-size:12px">Online = heartbeat within 90 s · Warning = 90 s–5 min, upload failures, or large backlog · Offline = silent for over 5 min.</p>
  ${adm?'<div id="f_tok"></div>':''}`;
  P().querySelectorAll('tr.clickable').forEach(r=>r.onclick=()=>detail(r.dataset.id));
  if(adm){$('#f_add').onclick=enrollUI;tokens()}
}
async function tokens(){
  const t=await api('/api/enrollment-tokens');$('#f_tok').innerHTML=`<h3 style="margin:16px 0 8px">Enrollment tokens</h3><table class="tbl"><thead><tr><th>Label</th><th>Created by</th><th>Expires</th><th>State</th><th></th></tr></thead><tbody>
  ${t.slice(0,15).map(x=>`<tr><td>${esc(x.label)}</td><td>${esc(x.created_by)}</td><td>${esc(x.expires_at)}</td><td>${esc(x.state)}${x.used_by_agent?' → '+esc(x.used_by_agent):''}</td><td>${x.state==='active'?`<button class="btn ghost mini" data-rv="${x.id}">Revoke</button>`:''}</td></tr>`).join('')||'<tr><td colspan="5">None</td></tr>'}</tbody></table>`;
  $('#f_tok').querySelectorAll('[data-rv]').forEach(b=>b.onclick=async()=>{await api('/api/enrollment-tokens/'+b.dataset.rv+'/revoke','POST',{});tokens()});
}
function enrollUI(){
  openDrawer(`<div class="dt"><small>ENROLL</small><h2>Enroll an endpoint</h2></div><p>Give the token to the <b>device owner</b>. They run the agent installer, read what is collected and consent. The token works once and expires.</p>
   <label>Label <input id="f_lab" placeholder="FRIEND-PC"></label> <label>Expires in (min) <input id="f_exp" value="60" size="5"></label> <button class="btn mini" id="f_mk">Create token</button><div id="f_out" style="margin-top:12px"></div>`);
  $('#f_mk').onclick=async()=>{const d=await api('/api/enrollment-tokens','POST',{label:$('#f_lab').value,expires_minutes:+$('#f_exp').value||60}),H=location.host;
    $('#f_out').innerHTML=`<b>Token (shown once):</b><pre style="white-space:pre-wrap;user-select:all">${esc(d.token)}</pre><small>Expires ${esc(d.expires_at)}</small>
    <h4>Ubuntu / Debian</h4><pre style="white-space:pre-wrap;user-select:all">sudo ./install_linux.sh --server https://${esc(H)} --token ${esc(d.token)} [--ca-bundle ca.pem]</pre>
    <h4>Windows (Administrator PowerShell)</h4><pre style="white-space:pre-wrap;user-select:all">.\\install_windows.ps1 -Server https://${esc(H)} -Token ${esc(d.token)} [-CaBundle ca.pem]</pre>`;tokens()}
}
async function detail(id,f){
  cur=id;f=f||{};const a=await api('/api/agents/'+id),qs=new URLSearchParams(Object.entries(f).filter(([k,v])=>v)).toString(),ev=await api(`/api/agents/${id}/events?limit=200&${qs}`),h=a.health||{};
  openDrawer(`<div class="dt"><small>ENDPOINT</small><h2>${DOT[a.state]} ${esc(a.hostname)}</h2></div>
  <div class="grid" style="display:grid;grid-template-columns:1fr 1fr;gap:10px"><div class="card"><h4>Host</h4><small>ID ${esc(a.id)}<br>OS ${esc(a.os)} ${esc(a.os_version||'')}<br>IPs ${esc((a.ips||[]).join(', ')||a.ip||'')}<br>Agent ${esc(a.agent_version||'')} · credential ${esc(a.credential_id)}<br>Registered ${esc(a.registered_at)} by ${esc(a.enrolled_by||'')}<br>Monitoring: ${esc(a.monitoring)} · status ${esc(a.status)}</small></div>
   <div class="card"><h4>Agent health</h4><small>Last heartbeat ${ago(a.last_heartbeat)} · last success ${esc(h.last_success||'n/a')}<br>CPU ${Math.round(h.cpu||0)}% · RAM ${Math.round(h.mem||0)}% · uptime ${Math.round((h.uptime_s||0)/60)} min<br>Sent ${h.events_sent||0} · queued ${h.events_queued||0} · dropped ${h.dropped||0}<br>Upload failures ${h.upload_failures||0} · server reachable: ${h.server_reachable===false?'NO':'yes'}<br>Collectors: ${esc((h.collectors||[]).join(', '))}${(h.collector_errors||[]).length?'<br><span style="color:#f59e0b">'+esc(h.collector_errors.join('; '))+'</span>':''}</small></div></div>
  ${can('admin')&&a.status!=='revoked'?`<p><button class="btn ghost mini" id="f_rev">Revoke this agent</button></p>`:''}
  <h4>Alerts (${a.alerts.length}) — repeated detections are merged (×count)</h4><table class="tbl"><tbody>${a.alerts.slice(0,15).map(x=>`<tr><td>${pill(x.severity)}</td><td>${esc(x.title)} ${x.count>1?'<b>×'+x.count+'</b>':''}</td><td>${esc(x.updated)}</td><td>${esc(x.status)}</td></tr>`).join('')||'<tr><td>None</td></tr>'}</tbody></table>
  <h4>Events / timeline</h4><div class="bar"><select id="ff_category">${opts(CATS,f.category)}</select><select id="ff_severity">${opts(SEVS,f.severity)}</select><input id="ff_username" placeholder="username" value="${esc(f.username||'')}" size="10"><input id="ff_source" placeholder="source/channel" value="${esc(f.source||'')}" size="12"><input id="ff_rule" placeholder="detection rule" value="${esc(f.rule||'')}" size="14"><input id="ff_from" placeholder="from YYYY-MM-DD" value="${esc(f.from||'')}" size="12"><input id="ff_q" placeholder="text" value="${esc(f.q||'')}" size="10"><button class="btn mini" id="ff_go">Filter</button></div>
  <table class="tbl"><tbody>${ev.map(e=>`<tr><td>${esc(e.ts)}</td><td>${e.risk?pill(e.risk):''}</td><td>${esc(e.category||'')}</td><td>${esc(e.username||'')}</td><td>${esc((e.message||'').slice(0,160))}</td></tr>`).join('')||'<tr><td>No events match</td></tr>'}</tbody></table>`);
  $('#ff_go').onclick=()=>detail(id,Object.fromEntries(['category','severity','username','source','rule','from','q'].map(k=>[k,$('#ff_'+k).value.trim()])));
  const r=$('#f_rev');if(r)r.onclick=async()=>{if(confirm('Revoke '+a.hostname+'? Its credential stops working immediately.')){await api(`/api/agents/${id}/revoke`,'POST',{});toast('Agent revoked');list()}};
}
window.SOCX_FLEET={detail};   // reused by the Monitoring Center so both pages share one endpoint detail view
window.SOCX_PAGES.fleet={t:['Remote agents','Authorized endpoints reporting over HTTPS (Windows, Ubuntu, Debian)'],load(){list();clearInterval(timer);timer=setInterval(()=>{if(!document.hidden&&$('#drawer').hidden)list()},15000);
  if(window.io)io().on('fleet',()=>{clearTimeout(window._ft);window._ft=setTimeout(()=>{if($('#drawer').hidden)list();else if(cur)detail(cur)},700)})}};
})();
