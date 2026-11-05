/* EXE-SOC "Monitoring Center": Overview / Windows / Linux / Ubuntu / Cloud. Loaded after fleet.js, before app.js.
   Every number comes from /api/monitoring/* (derived from stored data at request time). Nothing is hardcoded or simulated. */
(function(){
window.SOCX_PAGES=window.SOCX_PAGES||{};
const TABS=[['overview','Overview'],['windows','Windows'],['linux','Linux'],['ubuntu','Ubuntu'],['cloud','Cloud']];
const DOT={never_connected:'⚪',online:'🟢',degraded:'🟡',offline:'🔴',revoked:'⛔'},LBL={never_connected:'Never connected',online:'Online',degraded:'Degraded',offline:'Offline',revoked:'Revoked'};
const STATES=['never_connected','online','degraded','offline','revoked'],SEVS=['','Critical','High','Medium','Low','Normal'],WINS=[['1h','Last hour'],['24h','Last 24 h'],['7d','Last 7 days'],['30d','Last 30 days']];
const ago=t=>{if(!t)return'never';const s=(Date.now()-new Date(t.replace(' ','T')))/1000;return s<90?Math.round(s)+' s ago':s<5400?Math.round(s/60)+' min ago':s<172800?Math.round(s/3600)+' h ago':Math.round(s/86400)+' d ago'};
const opt=(a,sel)=>a.map(v=>{const [k,l]=Array.isArray(v)?v:[v,v||'any'];return `<option value="${esc(k)}" ${k===sel?'selected':''}>${esc(l)}</option>`}).join('');
const qs=o=>Object.entries(o).filter(([k,v])=>v!==''&&v!=null).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
let tab='overview',timer=null,off=0;const F={state:'',q:'',ip:'',severity:'',since:'24h',env:'',tag:''};
const LIMIT=50;

function shell(){
  P().innerHTML=`<div class="tabs" id="mc_tabs" style="flex-wrap:wrap;margin-bottom:12px">${TABS.map(([k,l])=>`<button class="btn mini ${k===tab?'':'ghost'}" data-tab="${k}">${esc(l)}</button>`).join('')}</div><div id="mc_body"></div>`;
  $$('#mc_tabs [data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;off=0;shell();show()});
}
const trunc=d=>d.truncated?`<div class="card" style="border-left:3px solid #f97316;margin-bottom:8px"><b>Partial view:</b> this deployment has more than ${d.max_endpoints} endpoints; only the first ${d.max_endpoints} (by hostname) are included in these counts and lists.</div>`:'';
function notReady(d){ // the API says the database migration is pending: say so, show no numbers
  $('#mc_body').innerHTML=`<div class="card"><h3>Monitoring Center is not ready</h3><p>${esc(d.error)}</p><p style="color:var(--muted)">${esc(d.hint||'')}</p></div>`;
}
async function show(quiet){
  if(!$('#mc_body'))return;
  if(tab==='overview')return overview();
  if(tab==='cloud')return cloud();
  return endpoints(tab);
}
async function overview(){
  const d=await api('/api/monitoring/overview?since='+encodeURIComponent(F.since));
  if(!$('#mc_body'))return; if(d.error)return notReady(d);
  const t=d.totals,th=d.thresholds,cls=['windows','linux','ubuntu','unknown'];
  $('#mc_body').innerHTML=trunc(d)+`<div class="bar" style="margin-bottom:10px"><b>${t.endpoints} endpoint(s)</b> <span>${STATES.map(s=>`${DOT[s]} ${t.by_state[s]} ${esc(LBL[s].toLowerCase())}`).join(' · ')}</span>
    <label style="margin-left:auto">Alerts / events window <select id="mc_win">${opt(WINS,F.since)}</select></label></div>
   <div class="kv" style="grid-template-columns:repeat(4,1fr)">${cls.map(c=>{const k=d.classes[c],al=Object.entries(k.alerts_in_window).map(([s,n])=>`${esc(s)} ${n}`).join(', ')||'none';
     return `<div class="card rkc" ${c==='unknown'?'':`data-go="${c}"`}><small>${esc(k.label)}</small><b>${k.total}</b><small>${STATES.filter(s=>k.by_state[s]).map(s=>`${DOT[s]} ${k.by_state[s]}`).join(' ')||'no endpoints'}</small><br><small>Alerts: ${esc(al)}</small><br><small>Events: ${k.events_in_window}</small></div>`}).join('')}</div>
   <div class="card" style="margin-top:12px"><h3>Cloud</h3><p><span class="pill s-normal">${esc(d.cloud.state)}</span> ${esc(d.cloud.message)}</p></div>
   <p style="color:var(--muted);font-size:12px;margin-top:10px">States: <b>Online</b> = heartbeat within ${th.online_seconds} s and no problem · <b>Degraded</b> = heartbeat up to ${th.offline_seconds} s old, or recent upload failures (3+), more than ${th.degraded_queue_over} queued events, or collector errors · <b>Offline</b> = silent for over ${th.offline_seconds} s · <b>Never connected</b> = enrolled but nothing received yet · <b>Revoked</b> = credential revoked. Times are server local time. Generated ${esc(d.generated_at)}.</p>`;
  $('#mc_win').onchange=e=>{F.since=e.target.value;overview()};
  $$('#mc_body [data-go]').forEach(c=>c.onclick=()=>{tab=c.dataset.go;off=0;shell();show()});
}
function cloudCard(c){return `<div class="card"><h3>Cloud monitoring <span class="pill s-normal">${esc(c.state)}</span></h3><p>${esc(c.message)}</p><p style="color:var(--muted)">Connectors configured: <b>${c.connectors}</b>. Nothing is monitored and no cloud data or demo data is shown. A connector will only appear here after an administrator has configured credentials and permissions.</p></div>`}
async function cloud(){
  const d=await api('/api/monitoring/overview?since=1h'); if(!$('#mc_body'))return; if(d.error)return notReady(d);
  $('#mc_body').innerHTML=cloudCard(d.cloud);
}
async function endpoints(os){
  const d=await api('/api/monitoring/endpoints?'+qs({os,state:F.state,q:F.q,ip:F.ip,severity:F.severity,since:F.since,env:F.env,tag:F.tag,limit:LIMIT,offset:off}));
  if(!$('#mc_body'))return; if(d.error&&d.total===undefined)return notReady(d);
  const adm=can('admin'),items=d.items||[],title={windows:'Windows',linux:'Linux (other distributions)',ubuntu:'Ubuntu'}[os];
  $('#mc_body').innerHTML=trunc(d)+`<div class="bar" style="margin-bottom:8px;flex-wrap:wrap;gap:8px"><b>${esc(title)}: ${d.total} endpoint(s)</b>
    <label>State <select id="mc_st">${opt([['','any'],...STATES.map(s=>[s,LBL[s]])],F.state)}</select></label>
    <label>Hostname <input id="mc_q" value="${esc(F.q)}" size="12"></label><label>IP <input id="mc_ip" value="${esc(F.ip)}" size="12"></label>
    <label>Has alerts of severity <select id="mc_sev">${opt(SEVS,F.severity)}</select></label><label>Window <select id="mc_win">${opt(WINS,F.since)}</select></label>
    <label>Environment <input id="mc_env" value="${esc(F.env)}" size="8"></label><label>Tag <input id="mc_tag" value="${esc(F.tag)}" size="8"></label>
    <button class="btn mini" id="mc_apply">Apply</button><button class="btn ghost mini" id="mc_clear">Clear</button></div>
   ${items.length?`<table class="tbl"><thead><tr><th></th><th>Endpoint</th><th>OS</th><th>Agent</th><th>Last heartbeat</th><th>Last event received</th><th>Alerts (window)</th><th>Events (window)</th><th>Environment / tags</th>${adm?'<th></th>':''}</tr></thead><tbody>
   ${items.map(x=>{const al=Object.entries(x.alerts_in_window.by_severity).map(([s,n])=>`${pill(s)} ${n}`).join(' ')||'0';
     const osd=os==='windows'?esc(x.os_version||x.os||''):`${esc(x.distro_id&&x.distro_id!=='unknown'?x.distro_id:'distribution unknown')} ${esc(x.distro_version||'')}`;
     return `<tr class="clickable" data-id="${esc(x.id)}"><td title="${esc(x.state_reason)}">${DOT[x.state]||''}<br><small>${esc(LBL[x.state]||x.state)}</small></td><td><b>${esc(x.hostname)}</b><br><small>${esc(x.id)}</small></td>
     <td>${osd}${x.classified_by==='legacy_os_name'||x.classified_by==='family_only'?`<br><small title="Older agent: classification from the OS name it reports. Update the agent for exact /etc/os-release data.">(limited metadata)</small>`:''}</td>
     <td>${esc(x.agent_version||'')}</td><td>${ago(x.last_heartbeat)}</td><td>${ago(x.last_event_at)}</td><td>${al}</td><td>${x.events_in_window}</td>
     <td>${esc(x.environment||'')}${x.tags.length?'<br>'+x.tags.map(t=>`<span class="pill s-normal">${esc(t)}</span>`).join(' '):''}</td>${adm?`<td><button class="btn ghost mini" data-edit="${esc(x.id)}">Edit</button></td>`:''}</tr>`}).join('')}</tbody></table>
   <div class="bar" style="margin-top:8px"><button class="btn ghost mini" id="mc_prev" ${off?'':'disabled'}>‹ Prev</button> <span>${d.total?off+1:0}–${off+items.length} of ${d.total}</span> <button class="btn ghost mini" id="mc_next" ${off+LIMIT<d.total?'':'disabled'}>Next ›</button></div>`
   :`<div class="card"><p><b>No endpoints match.</b></p><p style="color:var(--muted)">${F.state||F.q||F.ip||F.severity||F.env||F.tag?'Clear the filters to see every '+esc(title)+' endpoint.':'No '+esc(title)+' endpoints are enrolled. Enroll one from <a href="/fleet">Remote agents</a>; it appears here after its first heartbeat reports its operating system.'}</p></div>`}
   <p style="color:var(--muted);font-size:12px">Window and alert counts use server local time. Clicking a row opens the existing endpoint detail.</p>`;
  const apply=()=>{F.state=$('#mc_st').value;F.q=$('#mc_q').value.trim();F.ip=$('#mc_ip').value.trim();F.severity=$('#mc_sev').value;F.since=$('#mc_win').value;F.env=$('#mc_env').value.trim();F.tag=$('#mc_tag').value.trim().toLowerCase();off=0;endpoints(os)};
  $('#mc_apply').onclick=apply;$('#mc_clear').onclick=()=>{Object.assign(F,{state:'',q:'',ip:'',severity:'',since:'24h',env:'',tag:''});off=0;endpoints(os)};
  const pv=$('#mc_prev'),nx=$('#mc_next');if(pv)pv.onclick=()=>{off=Math.max(0,off-LIMIT);endpoints(os)};if(nx)nx.onclick=()=>{off+=LIMIT;endpoints(os)};
  $$('#mc_body tr.clickable').forEach(r=>r.onclick=e=>{if(e.target.closest('[data-edit]'))return;if(window.SOCX_FLEET)window.SOCX_FLEET.detail(r.dataset.id)});
  $$('#mc_body [data-edit]').forEach(b=>b.onclick=()=>editMeta(items.find(i=>i.id===b.dataset.edit),os));
}
function editMeta(x,os){
  if(!x)return;
  openDrawer(`<div class="dt"><small>ENDPOINT METADATA</small><h2>${esc(x.hostname)}</h2></div><p style="color:var(--muted)">Environment and tags are labels for filtering. Changes are recorded in the audit log.</p>
   <label>Environment <input id="mc_e_env" value="${esc(x.environment||'')}" maxlength="32" placeholder="production"></label>
   <label style="display:block;margin-top:8px">Tags (comma separated, up to 10) <input id="mc_e_tags" value="${esc(x.tags.join(', '))}" style="width:100%" placeholder="web, dmz"></label>
   <p class="err" id="mc_e_err"></p><button class="btn mini" id="mc_e_save">Save</button>`);
  $('#mc_e_save').onclick=async()=>{
    const tags=$('#mc_e_tags').value.split(',').map(s=>s.trim()).filter(Boolean),r=await api(`/api/monitoring/endpoints/${encodeURIComponent(x.id)}/meta`,'POST',{environment:$('#mc_e_env').value.trim(),tags});
    if(r.ok){toast('Saved');$('#drawerBg').click();endpoints(os)}else $('#mc_e_err').textContent=r.error||'Not saved';
  };
}
window.SOCX_PAGES.monitoring={t:['Monitoring Center','Windows, Linux, Ubuntu and Cloud monitoring status from stored, verified data'],load(){shell();show();clearInterval(timer);timer=setInterval(()=>{if(!document.hidden&&$('#drawer').hidden&&$('#mc_body'))show(true)},30000)}};
})();
