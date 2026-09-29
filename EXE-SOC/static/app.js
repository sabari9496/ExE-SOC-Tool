/* SOC frontend – talks to the Flask REST API. */
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const page=document.body.dataset.page,ROLE=document.body.dataset.role,RK={viewer:1,analyst:2,admin:3},can=r=>RK[ROLE]>=RK[r];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(u,m='GET',b){const r=await fetch(u,{method:m,headers:{'Content-Type':'application/json','X-Requested-With':'fetch'},body:b?JSON.stringify(b):undefined});
 if(r.status===401){location='/login';return{}}const d=await r.json().catch(()=>({}));if(!r.ok&&d.error){toast(d.error,'High',1)}return d}
const COL={Critical:'#ef3b4f',High:'#f97316',Medium:'#eab308',Low:'#3b82f6'};
const pill=s=>`<span class="pill s-${String(s).toLowerCase()}">${esc(s)}</span>`;
const stc=s=>'st-'+String(s).toLowerCase().replace(/\s+/g,'');
const hm=t=>t?String(t).slice(11,16):'';
function toast(t,sev,err){const d=document.createElement('div');d.style.borderLeftColor=err?'#f97316':(COL[sev]||'#3b82f6');d.textContent=t;$('#toast').appendChild(d);setTimeout(()=>d.remove(),5000)}
Chart.defaults.color='#8a95ad';Chart.defaults.borderColor='#182342';
if(localStorage.theme==='light')document.body.classList.add('light');
$('#theme').onclick=()=>{document.body.classList.toggle('light');localStorage.theme=document.body.classList.contains('light')?'light':'dark'};
const setBadge=n=>['bellBadge','navBadge'].forEach(i=>{const e=$('#'+i);e.textContent=n;e.dataset.z=n?0:1});

/* search */
let st;$('#gs').oninput=e=>{clearTimeout(st);const v=e.target.value.trim(),dd=$('#dd');if(v.length<3){dd.hidden=true;return}
 st=setTimeout(async()=>{const r=await api('/api/search?q='+encodeURIComponent(v));dd.innerHTML=r.length?r.map(i=>`<a href="${i.type==='alert'?'#':i.url}" ${i.type==='alert'?`data-alert="${i.id}"`:''}><small>${i.type}</small>${esc(i.text)}</a>`).join(''):'<a>No results</a>';dd.hidden=false},250)};
document.addEventListener('click',e=>{if(!e.target.closest('.search'))$('#dd').hidden=true});

/* charts */
function donut(id,data,colors){const c=$('#'+id);c._ch&&c._ch.destroy();c._ch=new Chart(c,{type:'doughnut',data:{datasets:[{data,backgroundColor:colors,borderWidth:0}]},options:{cutout:'70%',plugins:{legend:{display:false},tooltip:{enabled:false}},animation:false}})}
function gauge(id,v,col){const c=$('#'+id);c._ch&&c._ch.destroy();c._ch=new Chart(c,{type:'doughnut',data:{datasets:[{data:[v,100-v],backgroundColor:[col,'#1b2543'],borderWidth:0}]},options:{rotation:-90,circumference:180,cutout:'75%',plugins:{legend:{display:false},tooltip:{enabled:false}},animation:false,responsive:true,maintainAspectRatio:false}})}
let LMAP;function drawMap(pts,home,full){
 if(!LMAP){LMAP=L.map('map',{zoomControl:full}).setView([20,10],2);L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'&copy; OSM &copy; CARTO'}).addTo(LMAP);LMAP._g=L.layerGroup().addTo(LMAP);new ResizeObserver(()=>LMAP.invalidateSize()).observe($('#map'))}
 LMAP._g.clearLayers();const b=[];pts.forEach(p=>{const c=COL[p.severity]||'#3b82f6';
  if(home&&(p.lat!==home[0]||p.lon!==home[1]))L.polyline([[p.lat,p.lon],home],{color:c,weight:1,opacity:.35,dashArray:'4 6'}).addTo(LMAP._g);
  L.circleMarker([p.lat,p.lon],{radius:full?8:6,color:c,fillColor:c,fillOpacity:.6,weight:2}).bindPopup(`<b>${esc(p.title)}</b><br>${esc(p.source_ip)} · ${esc(p.country||'')}`).addTo(LMAP._g);b.push([p.lat,p.lon])});
 if(full&&b.length)LMAP.fitBounds(b,{padding:[40,40],maxZoom:4})}

/* live status (sidebar, gauges, badge) */
async function pulse(){const s=await api('/api/system');if(s.cpu===undefined)return;setBadge(s.badge);
 if($('#vCpu')){$('#vCpu').textContent=Math.round(s.cpu)+'%';$('#vRam').textContent=Math.round(s.ram)+'%';gauge('gCpu',s.cpu,'#3b82f6');gauge('gRam',s.ram,'#8b5cf6')}
 const bad=s.cpu>90||s.ram>95||s.disk>95;$('#sysDot').style.background=bad?'#ef3b4f':'#22c55e';$('#sysTxt').textContent=bad?'Resource pressure':'All Systems Operational';$('#sysTxt').style.color=bad?'#ef3b4f':''}

/* dashboard */
const KP=[['total','Total Alerts','bell','red'],['Critical','Critical Alerts','shield','red'],['High','High Alerts','bell','orange'],['Medium','Medium Alerts','bell','yellow'],['Low','Low Alerts','bell','blue'],['Resolved','Resolved','target','green']];
async function dash(){const d=await api('/api/dashboard');if(!d.kpi)return;
 $('#kpis').innerHTML=KP.map(([k,l,i,c])=>{const v=d.kpi[k],up=v.delta>=0,good=k==='Resolved'?up:!up;
  return`<div class="card kpi"><div class="ico c-${c}"><svg class="ic"><use href="#i-${i}"/></svg></div><div><small>${l}</small><b>${v.value}</b><em><span class="${good?'dn':'up'}">${up?'↑':'↓'} ${Math.abs(v.delta)}%</span> from yesterday</em></div></div>`}).join('');
 const s=d.severity,tot=Object.values(s).reduce((a,b)=>a+b,0);$('#sevTotal').textContent=tot;
 $('#sevLegend').innerHTML=Object.keys(COL).map(k=>`<div><span><i style="background:${COL[k]}"></i>${k}</span><span>${s[k]} (${tot?Math.round(s[k]*100/tot):0}%)</span></div>`).join('');
 donut('cSev',Object.keys(COL).map(k=>s[k]),Object.values(COL));
 const tc=$('#cTime2');tc._ch&&tc._ch.destroy();tc._ch=new Chart(tc,{type:'line',data:{labels:d.timeline.labels,datasets:[{data:d.timeline.data,borderColor:'#ef3b4f',backgroundColor:'rgba(239,59,79,.18)',fill:true,tension:.4,pointRadius:2}]},options:{maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0}},x:{ticks:{maxTicksLimit:7}}},animation:false}});
 const mx=d.top_ips[0]?.c||1,cl=['#ef3b4f','#f97316','#eab308','#3b82f6','#22c55e'];
 $('#topIps').innerHTML=d.top_ips.map((t,i)=>`<div><span>${esc(t.ip)}</span><span class="t"><i style="width:${t.c*100/mx}%;background:${cl[i]}"></i></span><span>${t.c}</span></div>`).join('')||'<div class="empty">No attackers yet.</div>';
 const e=d.endpoints;$('#endTotal').textContent=e.total;$('#endLegend').innerHTML=[['Online','#22c55e'],['Offline','#ef3b4f'],['At Risk','#f97316'],['Inactive','#8a95ad']].map(([k,c])=>`<div><span><i style="background:${c}"></i>${k}</span><span>${e[k]} (${e.total?Math.round(e[k]*100/e.total):0}%)</span></div>`).join('');
 donut('cEnd',[e.Online,e.Offline,e['At Risk'],e.Inactive],['#22c55e','#ef3b4f','#f97316','#8a95ad']);
 $('#recent').innerHTML=d.recent.map(a=>`<div class="al" data-alert="${a.id}" style="cursor:pointer">${pill(a.severity)}<div>${esc(a.title)}<small>${esc(a.source_ip)}</small></div><small>${hm(a.ts)}</small></div>`).join('')||'<div class="empty">No alerts.</div>';
 $('#events').innerHTML=d.events.map(a=>`<tr><td>${esc(a.ts)}</td><td>${pill(a.severity)}</td><td>${ipl(a.source_ip)}</td><td><a class="al-link" data-alert="${a.id}">${esc(a.title)}</a></td><td>${esc(a.dest_ip||'—')}</td><td class="${stc(a.status)}">${esc(a.status)}</td></tr>`).join('');
 drawMap(d.map,d.home,false);setBadge(d.badge)}
function clock(){const n=new Date();$('#cDate').textContent=n.toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'});$('#cTime').textContent=n.toLocaleTimeString()}

/* generic page helpers */
const P=()=>$('#pBody');
const opt=(a,sel)=>a.map(v=>`<option ${v===sel?'selected':''}>${v}</option>`).join('');
const tbl=(head,rows)=>`<div class="card tw"><table><thead><tr>${head.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')||`<tr><td colspan="${head.length}" class="empty">Nothing to show yet.</td></tr>`}</tbody></table></div>`;
const btn=(t,a,cls='ghost')=>`<button class="btn ${cls} mini" data-a="${a}">${t}</button>`;
const val=id=>$('#'+id).value.trim();
function head(t,s){$('#pTitle').textContent=t;$('#pSub').textContent=s}
let ACT={};document.addEventListener('click',e=>{const b=e.target.closest('[data-a]');if(b&&ACT[b.dataset.a])ACT[b.dataset.a](b.dataset)});
document.addEventListener('change',e=>{const s=e.target.closest('[data-c]');if(s&&ACT[s.dataset.c])ACT[s.dataset.c](s.dataset,s.type==='checkbox'?s.checked:s.value)});
const SEV=['Critical','High','Medium','Low'];

/* ===== Investigation drawer (Splunk-style drill-down) ===== */
const ipl=ip=>ip?`<a class="ip-link mono" data-ip="${esc(ip)}">${esc(ip)}</a>`:'—';
const kvrow=(k,v)=>`<div class="kvr"><span>${k}</span><span>${v}</span></div>`;
const spark=(a,c='#ef3b4f')=>{const m=Math.max(...a,1),w=240,h=40,st=w/(a.length-1||1);return`<svg viewBox="0 0 ${w} ${h}" class="spark"><polyline fill="none" stroke="${c}" stroke-width="1.6" points="${a.map((v,i)=>`${(i*st).toFixed(1)},${(h-3-(v/m)*(h-8)).toFixed(1)}`).join(' ')}"/></svg>`};
const bars=(l)=>{const m=Math.max(...l.map(i=>i.c),1);return l.map(i=>`<div class="mb"><span>${esc(i.k)}</span><span class="t"><i style="width:${i.c*100/m}%"></i></span><b>${i.c}</b></div>`).join('')||'<div class="empty">None</div>'};
const evTable=r=>`<div class="tw dtw"><table><thead><tr><th>Time</th><th>Dest</th><th>Host</th><th>Raw message</th></tr></thead><tbody>${r.map(e=>`<tr class="${e.hl?'hl':''}"><td>${esc(e.ts)}</td><td>${esc(e.dest_ip||'—')}</td><td>${esc(e.host||'—')}</td><td class="mono">${esc(e.message)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No events</td></tr>'}</tbody></table></div>`;
const alTable=r=>`<div class="tw dtw"><table><thead><tr><th>ID</th><th>Time</th><th>Severity</th><th>Alert</th><th>Status</th></tr></thead><tbody>${r.map(a=>`<tr><td><a class="al-link" data-alert="${a.id}">#${a.id}</a></td><td>${esc(a.ts)}</td><td>${pill(a.severity)}</td><td>${esc(a.title)}${a.count>1?` ×${a.count}`:''}</td><td class="${stc(a.status)}">${esc(a.status||'')}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">None</td></tr>'}</tbody></table></div>`;
function openDrawer(html){$('#drawer').innerHTML=`<div class="dh"><button class="btn ghost mini" data-a="dx">✕ Close</button></div>${html}`;$('#drawer').hidden=$('#drawerBg').hidden=false;$('#drawer').scrollTop=0}
function closeDrawer(){$('#drawer').hidden=$('#drawerBg').hidden=true}
$('#drawerBg').onclick=closeDrawer;document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer()});
document.addEventListener('click',e=>{
 const a=e.target.closest('[data-alert]');if(a){e.preventDefault();openAlert(a.dataset.alert);return}
 const p=e.target.closest('[data-ip]:not(button)');if(p&&p.classList.contains('ip-link')){e.preventDefault();openIP(p.dataset.ip);return}
 const b=e.target.closest('[data-a="dx"]');if(b)closeDrawer()});
const ipProfileHTML=p=>`<div class="kv">
 <div class="card"><small>Risk</small><b>${pill(p.risk)}</b></div><div class="card"><small>Risk score</small><b>${p.risk_score}/100</b></div>
 <div class="card"><small>Alerts / events</small><b>${p.alerts} / ${p.events}</b></div><div class="card"><small>Country</small><b style="font-size:16px">${esc(p.country)}</b></div></div>
 <div class="dsec"><h4>Reputation &amp; status</h4>${kvrow('Type',p.private?'Private / internal':'Public')}${kvrow('Known IOC',p.ioc?`<span class="pill s-critical">Yes</span> ${esc(p.ioc.source||'')}`:'No')}${kvrow('Blocklist',p.blocked?`<span class="pill s-critical">Blocked</span> ${esc(p.blocked.reason)} <small>(${esc(p.blocked.added_by)}, ${esc(p.blocked.ts)})</small>`:'Not blocked')}${kvrow('First seen',esc(p.first_seen||'—'))}${kvrow('Last seen',esc(p.last_seen||'—'))}${kvrow('Total alert hits',p.total_hits)}${kvrow('Existing cases',p.cases.map(c=>`#${c.id} ${esc(c.title)} (${c.status})`).join('<br>')||'None')}</div>
 <div class="dsec"><h4>Activity — last 24 h</h4>${spark(p.timeline)}</div>
 <div class="dsec dcols"><div><h4>Attack types</h4>${bars(p.by_title)}</div><div><h4>Targeted hosts / IPs</h4>${bars(p.targets)}</div><div><h4>Targeted ports</h4>${bars(p.ports)}</div></div>
 <div class="dsec"><h4>MITRE ATT&amp;CK techniques</h4>${p.mitre.map(m=>`<span class="tag">${esc(m.id)} · ${esc(m.name)} <small>${esc(m.tactic)}</small></span>`).join('')||'<div class="empty">None mapped</div>'}</div>
 <div class="dsec"><h4>All alerts from this IP</h4>${alTable(p.alert_list)}</div>
 <div class="dsec"><h4>Raw events (latest 50)</h4>${evTable(p.raw_events)}</div>`;
const ipActions=p=>can('analyst')&&!p.private?`<div class="bar">${p.blocked?`<button class="btn ghost mini" data-a="dun" data-ip="${esc(p.ip)}">Unblock IP</button>`:`<button class="btn red mini" data-a="dbl" data-ip="${esc(p.ip)}">Block IP</button>`}${p.ioc?'':`<button class="btn ghost mini" data-a="dioc" data-ip="${esc(p.ip)}">Add to IOCs</button>`}<button class="btn ghost mini" data-a="dspl" data-q="index=events source_ip=${esc(p.ip)} | sort -id">Search logs (SPL)</button></div>`:`<div class="bar"><button class="btn ghost mini" data-a="dspl" data-q="index=events source_ip=${esc(p.ip)} | sort -id">Search logs (SPL)</button></div>`;
async function openIP(ip){ip=(ip||'').trim();if(!ip)return;const p=await api('/api/investigate/ip/'+encodeURIComponent(ip));if(p.error)return;
 openDrawer(`<div class="dt"><small>IP INVESTIGATION</small><h2 class="mono">${esc(p.ip)}</h2></div>${ipActions(p)}${ipProfileHTML(p)}`)}
async function openAlert(id){const d=await api('/api/alerts/'+id+'/detail');if(d.error)return;const a=d.alert,hl=new Set(d.events.map(e=>e.id));
 openDrawer(`<div class="dt"><small>ALERT #${a.id} · ${esc(a.category)}</small><h2>${esc(a.title)} ${pill(a.severity)}</h2></div>
 <div class="bar">${can('analyst')?`<select class="sel" data-c="dst" data-id="${a.id}">${opt(['New','In Progress','Resolved'],a.status)}</select><button class="btn ghost mini" data-a="dasg" data-id="${a.id}">Assign to me</button><button class="btn ghost mini" data-a="dcs" data-id="${a.id}">Create case</button>${a.source_ip&&!a.blocked?`<button class="btn red mini" data-a="dbl" data-ip="${esc(a.source_ip)}" data-id="${a.id}">Block ${esc(a.source_ip)}</button>`:''}`:''}</div>
 <div class="dsec"><h4>Alert details</h4>${kvrow('Time (first)',esc(a.ts))}${kvrow('Last updated',esc(a.updated))}${kvrow('Occurrences',a.count)}${kvrow('Status',`<span class="${stc(a.status)}">${esc(a.status)}</span>`)}${kvrow('Owner',esc(a.assignee||'Unassigned'))}${kvrow('Source IP',ipl(a.source_ip)+(a.blocked?' <span class="pill s-critical">Blocked</span>':'')+(a.ioc?' <span class="pill s-high">IOC</span>':''))}${kvrow('Destination',esc(a.dest_ip||'—'))}${kvrow('Location',esc(a.country||'Unknown'))}${kvrow('Endpoint',a.endpoint?`${esc(a.endpoint)} (${esc(a.endpoint_ip||'')}, ${esc(a.endpoint_os||'')})${a.endpoint_isolated?' <span class="pill s-high">Isolated</span>':''}`:'—')}${a.note?kvrow('Escalation reason',`<b style="color:var(--orange)">${esc(a.note)}</b>`):''}${kvrow('Message',`<span class="mono">${esc(a.message)}</span>`)}${d.mitre?kvrow('MITRE ATT&CK',`<a class="tag" target="_blank" rel="noopener" href="${esc(d.mitre.url)}">${esc(d.mitre.id)} · ${esc(d.mitre.name)} <small>${esc(d.mitre.tactic)}</small></a>`):''}</div>
 <div class="dsec"><h4>Recommended actions</h4><ul class="rec">${d.recommended.map(r=>`<li>${esc(r)}</li>`).join('')}</ul></div>
 <div class="dsec"><h4>Events that triggered this alert (${d.events.length})</h4>${evTable(d.events)}</div>
 <div class="dsec"><h4>Surrounding activity from ${esc(a.source_ip||'source')} (±30 min)</h4>${evTable(d.context.map(e=>({...e,hl:hl.has(e.id)})))}</div>
 ${d.related_endpoint.length?`<div class="dsec"><h4>Other alerts on ${esc(a.endpoint)}</h4>${alTable(d.related_endpoint)}</div>`:''}
 <div class="dsec"><h4>Analyst activity</h4>${can('analyst')?`<div class="bar"><input id="dnote" size="40" placeholder="Add an investigation note"><button class="btn mini" data-a="dnt" data-id="${a.id}">Add note</button></div>`:''}${d.activity.map(x=>kvrow(esc(x.ts)+' · '+esc(x.user),esc(x.action))).join('')||'<div class="empty">No activity yet.</div>'}${d.cases.length?kvrow('Linked cases',d.cases.map(c=>`#${c.id} ${esc(c.title)} (${c.status})`).join('<br>')):''}</div>
 ${d.ip?`<div class="dsec dip"><h4>Full profile of ${esc(a.source_ip)}</h4>${ipProfileHTML(d.ip)}</div>`:''}`)}
const DA={
 dst:async(d,v)=>{await api('/api/alerts/'+d.id,'PATCH',{status:v});openAlert(d.id)},
 dasg:async d=>{await api('/api/alerts/'+d.id,'PATCH',{assignee:document.body.dataset.user});openAlert(d.id)},
 dcs:async d=>{const r=await api('/api/alerts/'+d.id+'/case','POST');r.id&&toast('Case #'+r.id+' created');openAlert(d.id)},
 dnt:async d=>{const v=$('#dnote').value.trim();if(v){await api('/api/alerts/'+d.id+'/note','POST',{note:v});openAlert(d.id)}},
 dbl:async d=>{if(!confirm('Block '+d.ip+'?'))return;const r=await api('/api/blocklist','POST',{ip:d.ip,reason:'Manual block from investigation'});r.ok&&toast('Blocked '+d.ip);d.id?openAlert(d.id):openIP(d.ip)},
 dun:async d=>{await api('/api/blocklist/'+encodeURIComponent(d.ip),'DELETE');openIP(d.ip)},
 dioc:async d=>{const r=await api('/api/iocs','POST',{value:d.ip,source:'Added from investigation'});r.ok&&toast('Added to IOCs');openIP(d.ip)},
 dspl:d=>{sessionStorage.splq=d.q;location="/search"}};
document.addEventListener('click',e=>{const b=e.target.closest('[data-a]');if(b&&DA[b.dataset.a])DA[b.dataset.a](b.dataset)});
document.addEventListener('change',e=>{const s=e.target.closest('[data-c]');if(s&&DA[s.dataset.c])DA[s.dataset.c](s.dataset,s.value)});

const PAGES={
alerts:{t:['Alerts','Triage, assign and resolve detections'],async load(){
  P().innerHTML=`<div class="bar"><input id="fq" placeholder="Filter text / IP" size="22"><select id="fs"><option value="">All status</option>${opt(['New','In Progress','Resolved'])}</select><select id="fv"><option value="">All severity</option>${opt(SEV)}</select></div><div id="list"></div>`;
  ['fq','fs','fv'].forEach(i=>$('#'+i).oninput=PAGES.alerts.list);ACT={
   st:async(d,v)=>{await api('/api/alerts/'+d.id,'PATCH',{status:v});PAGES.alerts.list()},
   asg:async d=>{await api('/api/alerts/'+d.id,'PATCH',{assignee:document.body.dataset.user});PAGES.alerts.list()},
   blk:async d=>{if(confirm('Block '+d.ip+'?')){(await api('/api/alerts/'+d.id+'/block','POST')).ok&&toast('Blocked '+d.ip)}},
   cs:async d=>{const r=await api('/api/alerts/'+d.id+'/case','POST');r.id&&toast('Case #'+r.id+' created');PAGES.alerts.list()},
   del:async d=>{if(confirm('Delete alert?')){await api('/api/alerts/'+d.id,'DELETE');PAGES.alerts.list()}}};PAGES.alerts.list()},
  async list(){const p=new URLSearchParams({q:val('fq'),status:$('#fs').value,severity:$('#fv').value});const r=await api('/api/alerts?'+p);
   $('#list').innerHTML=tbl(['ID','Time','Severity','Alert','Source','Destination','Endpoint','Status','Owner',''],r.map(a=>`<tr><td><a class="al-link" data-alert="${a.id}">#${a.id}</a></td><td>${esc(a.ts)}</td><td>${pill(a.severity)}</td><td><a class="al-link" data-alert="${a.id}">${esc(a.title)}</a>${a.count>1?` <small>×${a.count}</small>`:''}<br><small class="mono">${esc((a.note||a.message||'').slice(0,80))}</small></td><td>${ipl(a.source_ip)}</td><td>${esc(a.dest_ip||'—')}</td><td>${esc(a.endpoint||'—')}</td>
   <td>${can('analyst')?`<select class="sel" data-c="st" data-id="${a.id}">${opt(['New','In Progress','Resolved'],a.status)}</select>`:`<span class="${stc(a.status)}">${a.status}</span>`}</td><td>${esc(a.assignee||'—')}</td>
   <td>${can('analyst')?btn('Assign to me','asg" data-id="'+a.id)+btn('Case','cs" data-id="'+a.id)+btn('Block IP','blk" data-id="'+a.id+'" data-ip="'+esc(a.source_ip)):''}${can('admin')?btn('✕','del" data-id="'+a.id,'red'):''}</td></tr>`))}},
endpoints:{t:['Endpoints','Agents reporting to this SOC (heartbeat via /api/agent/heartbeat)'],async load(){
  P().innerHTML=(can('analyst')?`<div class="bar"><input id="eh" placeholder="Hostname"><input id="ei" placeholder="IP"><input id="eo" placeholder="OS"><button class="btn" data-a="add">Add endpoint</button></div>`:'')+'<div id="list"></div>';
  ACT={add:async()=>{await api('/api/endpoints','POST',{hostname:val('eh'),ip:val('ei'),os:val('eo')});PAGES.endpoints.list()},iso:async d=>{await api('/api/endpoints/'+d.id,'PATCH',{isolated:d.v==='1'});PAGES.endpoints.list()},del:async d=>{if(confirm('Delete endpoint?')){await api('/api/endpoints/'+d.id,'DELETE');PAGES.endpoints.list()}}};PAGES.endpoints.list()},
  async list(){const r=await api('/api/endpoints'),C={Online:'st-resolved','At Risk':'st-progress',Offline:'st-new',Inactive:''};
   $('#list').innerHTML=tbl(['Hostname','IP','OS','Status','CPU','RAM','Open alerts','Last seen',''],r.map(e=>`<tr><td>${esc(e.hostname)}</td><td>${esc(e.ip||'—')}</td><td>${esc(e.os||'—')}</td><td class="${C[e.status]}">${e.status}${e.isolated?' (isolated)':''}</td><td>${Math.round(e.cpu)}%</td><td>${Math.round(e.ram)}%</td><td>${e.open_alerts}</td><td>${esc(e.last_seen||'—')}</td>
   <td>${can('analyst')?btn(e.isolated?'Release':'Isolate','iso" data-id="'+e.id+'" data-v="'+(e.isolated?0:1)):''}${can('admin')?btn('✕','del" data-id="'+e.id,'red'):''}</td></tr>`))}},
network:{t:['Network','Attack origins and blocked IPs'],async load(){
  P().innerHTML=`<div class="card" style="margin-bottom:14px"><div id="map" class="map" style="height:420px"></div></div>`+(can('analyst')?`<div class="bar"><input id="bi" placeholder="IP to block"><input id="br" placeholder="Reason" size="30"><button class="btn" data-a="add">Block IP</button></div>`:'')+'<div id="list"></div>';
  ACT={add:async()=>{const r=await api('/api/blocklist','POST',{ip:val('bi'),reason:val('br')});r.ok&&PAGES.network.list()},un:async d=>{await api('/api/blocklist/'+encodeURIComponent(d.ip),'DELETE');PAGES.network.list()}};
  const d=await api('/api/dashboard');drawMap(d.map,d.home,true);PAGES.network.list()},
  async list(){const r=await api('/api/blocklist');$('#list').innerHTML='<h3>Blocklist</h3>'+tbl(['IP','Reason','By','Time',''],r.map(b=>`<tr><td>${ipl(b.ip)}</td><td>${esc(b.reason)}</td><td>${esc(b.added_by)}</td><td>${esc(b.ts)}</td><td>${can('analyst')?btn('Unblock','un" data-ip="'+esc(b.ip)):''}</td></tr>`))}},
intel:{t:['Threat Intelligence','Look up an IP and manage indicators of compromise'],async load(){
  P().innerHTML=`<div class="bar"><input id="q" placeholder="e.g. 185.220.101.10" size="28"><button class="btn" data-a="go">Look up</button></div><div id="res" style="margin-bottom:14px"></div>`+(can('analyst')?`<div class="bar"><input id="iv" placeholder="IP or domain"><input id="is" placeholder="Source / note" size="26"><button class="btn" data-a="add">Add IOC</button></div>`:'')+'<div id="list"></div>';
  ACT={go:async()=>{openIP(val('q'));const r=await api('/api/intel/'+encodeURIComponent(val('q')));if(r.error){$('#res').innerHTML='';return}
    $('#res').innerHTML=`<div class="kv"><div class="card"><small>Risk</small><b>${pill(r.risk)}</b></div><div class="card"><small>Risk score</small><b>${r.risk_score}/100</b></div><div class="card"><small>Alerts</small><b>${r.alerts}</b></div><div class="card"><small>IOC / Blocked</small><b>${r.ioc?'IOC':'–'} / ${r.blocked?'Blocked':'–'}</b></div></div>`+tbl(['Time','Severity','Alert'],r.recent.map(a=>`<tr><td>${esc(a.ts)}</td><td>${pill(a.severity)}</td><td>${esc(a.title)}</td></tr>`))},
   add:async()=>{const r=await api('/api/iocs','POST',{value:val('iv'),source:val('is')});r.ok&&PAGES.intel.list()},del:async d=>{await api('/api/iocs/'+d.id,'DELETE');PAGES.intel.list()}};PAGES.intel.list()},
  async list(){const r=await api('/api/iocs');$('#list').innerHTML='<h3>Indicators of Compromise</h3>'+tbl(['Value','Type','Source','Added',''],r.map(i=>`<tr><td>${i.type==='ip'?ipl(i.value):esc(i.value)}</td><td>${i.type}</td><td>${esc(i.source)}</td><td>${esc(i.ts)}</td><td>${can('analyst')?btn('✕','del" data-id="'+i.id,'red'):''}</td></tr>`))}},
cases:{t:['Cases','Investigations, notes and linked alerts'],async load(){
  P().innerHTML=(can('analyst')?`<div class="bar"><input id="ct" placeholder="Case title" size="34"><select id="cp">${opt(['Medium','High','Low'])}</select><button class="btn" data-a="add">Create case</button></div>`:'')+'<div id="list"></div><div id="det" style="margin-top:14px"></div>';
  ACT={add:async()=>{const r=await api('/api/cases','POST',{title:val('ct'),priority:$('#cp').value});r.id&&PAGES.cases.list()},cst:async(d,v)=>{await api('/api/cases/'+d.id,'PATCH',{status:v});PAGES.cases.list()},
   view:async d=>{const c=await api('/api/cases/'+d.id);$('#det').innerHTML=`<div class="card"><h3>#${c.id} ${esc(c.title)}</h3><p style="color:var(--muted)">${esc(c.description||'')}</p><b>Linked alerts:</b> ${c.alerts.map(a=>pill(a.severity)+' '+esc(a.title)).join(' · ')||'none'}<div class="bar" style="margin-top:12px">${can('analyst')?`<input id="nn" size="50" placeholder="Add a note"><button class="btn" data-a="note" data-id="${c.id}">Add note</button>`:''}</div>${c.notes.map(n=>`<div class="stat"><span>${esc(n.author)} · ${esc(n.ts)}</span><span>${esc(n.note)}</span></div>`).join('')||'<div class="empty">No notes yet.</div>'}</div>`},
   note:async d=>{if(val('nn')){await api('/api/cases/'+d.id,'PATCH',{note:val('nn')});ACT.view(d)}}};PAGES.cases.list()},
  async list(){const r=await api('/api/cases');$('#list').innerHTML=tbl(['ID','Title','Priority','Status','Owner','Alerts','Notes','Created',''],r.map(c=>`<tr><td>#${c.id}</td><td>${esc(c.title)}</td><td>${esc(c.priority)}</td><td>${can('analyst')?`<select class="sel" data-c="cst" data-id="${c.id}">${opt(['Open','In Progress','Closed'],c.status)}</select>`:c.status}</td><td>${esc(c.assignee||'—')}</td><td>${c.alerts}</td><td>${c.notes}</td><td>${esc(c.created_at)}</td><td>${btn('Open','view" data-id="'+c.id)}</td></tr>`))}},
reports:{t:['Reports','Alert statistics and CSV export'],async load(){
  P().innerHTML=`<div class="bar"><select id="dy">${[1,7,30,90].map(d=>`<option value="${d}" ${d===7?'selected':''}>Last ${d} day${d>1?'s':''}</option>`).join('')}</select><button class="btn ghost" data-a="csv">Download CSV</button><button class="btn ghost" onclick="print()">Print</button></div><div id="list"></div>`;
  $('#dy').onchange=PAGES.reports.list;ACT={csv:()=>location='/api/reports/export.csv?days='+$('#dy').value};PAGES.reports.list()},
  async list(){const r=await api('/api/reports?days='+$('#dy').value),t=(h,a)=>tbl(h,a.map(i=>`<tr><td>${esc(i.k)}</td><td>${i.c}</td></tr>`));
   $('#list').innerHTML=`<div class="kv"><div class="card"><small>Alerts</small><b>${r.total}</b></div><div class="card"><small>Resolved</small><b>${r.resolved}</b></div><div class="card"><small>Mean time to resolve</small><b>${r.mttr_minutes} min</b></div><div class="card"><small>Resolution rate</small><b>${r.total?Math.round(r.resolved*100/r.total):0}%</b></div></div>
   <div class="card" style="margin-bottom:14px"><h3>Alerts per day</h3><div style="height:200px"><canvas id="rc"></canvas></div></div><div class="grid g4">${t(['Severity','Count'],r.by_severity)}${t(['Category','Count'],r.by_category)}${t(['Status','Count'],r.by_status)}${t(['Top source IP','Count'],r.top_ips)}</div>`;
   new Chart($('#rc'),{type:'bar',data:{labels:r.daily.map(d=>d.k),datasets:[{data:r.daily.map(d=>d.c),backgroundColor:'#3b82f6'}]},options:{maintainAspectRatio:false,plugins:{legend:{display:false}},animation:false}})}},
search:{t:['Search (SPL)','Splunk-style search across events and alerts'],async load(){
  const ex=[['Failed logins by IP',"index=events \"failed password\" | stats count by source_ip | sort -count | head 10"],['Critical alerts',"index=alerts severity=Critical | table id ts title source_ip status"],['Events per hour',"index=events | timechart span=1h"],['Top attack types',"index=alerts | top title"],['One IP',"index=events source_ip=185.220.101.10 | sort -id"]];
  P().innerHTML=`<div class="card"><div class="bar"><input id="sq" class="splq" placeholder='index=events source_ip=185.* "failed password" | stats count by source_ip | sort -count | head 10'><select id="se"><option value="">All time</option><option value="60">Last 60 min</option><option value="1440">Last 24 h</option><option value="10080">Last 7 days</option></select><button class="btn" data-a="run">Search</button></div><div>${ex.map(([l,q],i)=>`<a class="tag" data-a="ex" data-i="${i}">${l}</a>`).join('')}</div><small style="color:var(--muted)">Fields — events: source_ip dest_ip host message ts · alerts: source_ip dest_ip title severity category status assignee country message ts count. Operators: = != &gt; &lt; * wildcard, NOT. Commands: stats count by, top, timechart span=, sort, head, table, dedup.</small></div><div id="sres" style="margin-top:14px"></div>`;
  ACT={run:async()=>{const r=await api('/api/spl?q='+encodeURIComponent(val('sq'))+'&earliest='+$('#se').value);if(r.error){$('#sres').innerHTML=`<div class="card" style="border-color:var(--red)">${esc(r.error)}</div>`;return}
   const cell=(c,v)=>c==='source_ip'||c==='dest_ip'&&false?ipl(v):c==='id'&&r.index==='alerts'?`<a class="al-link" data-alert="${v}">#${v}</a>`:c==='message'?`<span class="mono">${esc(v)}</span>`:esc(v??'—');
   let chart='';if(r.columns.join()==='time,count'&&r.rows.length)chart='<div class="card" style="margin-bottom:14px"><div style="height:200px"><canvas id="sc"></canvas></div></div>';
   $('#sres').innerHTML=chart+`<small style="color:var(--muted)">${r.rows.length} result(s) from ${r.total} matching ${r.index}${r.truncated?' (showing first 1000)':''}</small>`+tbl(r.columns,r.rows.map(x=>`<tr>${r.columns.map(c=>`<td>${cell(c,x[c])}</td>`).join('')}</tr>`));
   if(chart)new Chart($('#sc'),{type:'bar',data:{labels:r.rows.map(x=>x.time),datasets:[{data:r.rows.map(x=>x.count),backgroundColor:'#3b82f6'}]},options:{maintainAspectRatio:false,plugins:{legend:{display:false}},animation:false}})},
   ex:d=>{$('#sq').value=ex[d.i][1];ACT.run()}};
  $('#sq').onkeydown=e=>{if(e.key==='Enter')ACT.run()};if(sessionStorage.splq){$('#sq').value=sessionStorage.splq;delete sessionStorage.splq;ACT.run()}}},
logs:{t:['Logs','Raw events and the audit trail'],async load(){
  P().innerHTML=`<div class="bar"><select id="lt"><option value="events">Events</option>${can('analyst')?'<option value="audit">Audit trail</option>':''}</select><input id="lq" placeholder="Filter"></div><div id="list"></div>`;$('#lt').onchange=$('#lq').oninput=PAGES.logs.list;PAGES.logs.list()},
  async list(){if($('#lt').value==='audit'){const r=await api('/api/audit');$('#list').innerHTML=tbl(['Time','User','Action'],r.map(a=>`<tr><td>${esc(a.ts)}</td><td>${esc(a.user)}</td><td>${esc(a.action)}</td></tr>`))}
   else{const r=await api('/api/events?q='+encodeURIComponent(val('lq')));$('#list').innerHTML=tbl(['Time','Source','Destination','Host','Message'],r.map(e=>`<tr><td>${esc(e.ts)}</td><td>${ipl(e.source_ip)}</td><td>${esc(e.dest_ip||'—')}</td><td>${esc(e.host||'—')}</td><td class="mono">${esc(e.message)}</td></tr>`))}}},
playbooks:{t:['Playbooks','Automated responses that run when a new alert matches'],async load(){
  P().innerHTML=(can('admin')?`<div class="bar"><input id="pn" placeholder="Playbook name" size="28"><select id="ps">${opt(SEV,'High')}</select><select id="pc"><option value="">Any category</option>${opt(['auth','web','malware','network','dns','system'])}</select><select id="pa">${opt(['block_ip','create_case','notify','isolate_endpoint'])}</select><button class="btn" data-a="add">Create</button></div>`:'')+'<div id="list"></div>';
  ACT={add:async()=>{const r=await api('/api/playbooks','POST',{name:val('pn'),min_severity:$('#ps').value,category:$('#pc').value,action:$('#pa').value});r.ok&&PAGES.playbooks.list()},tg:async(d,v)=>{await api('/api/playbooks/'+d.id,'PATCH',{enabled:v});PAGES.playbooks.list()},del:async d=>{await api('/api/playbooks/'+d.id,'DELETE');PAGES.playbooks.list()}};PAGES.playbooks.list()},
  async list(){const r=await api('/api/playbooks');$('#list').innerHTML=tbl(['Name','Trigger','Category','Action','Runs','Last run','Enabled',''],r.map(p=>`<tr><td>${esc(p.name)}</td><td>${pill(p.min_severity)}+</td><td>${esc(p.category||'any')}</td><td class="mono">${p.action}</td><td>${p.runs}</td><td>${esc(p.last_run||'—')}</td><td><input type="checkbox" data-c="tg" data-id="${p.id}" ${p.enabled?'checked':''} ${can('admin')?'':'disabled'}></td><td>${can('admin')?btn('✕','del" data-id="'+p.id,'red'):''}</td></tr>`))}},
settings:{t:['Settings','Detection thresholds, geolocation and integration'],async load(){
  const s=await api('/api/settings'),F=[['org_name','Organisation name'],['home_lat','Home latitude (map)'],['home_lon','Home longitude (map)'],['brute_threshold','Brute-force threshold (failed logins)'],['brute_window_min','Brute-force window (min)'],['dedupe_seconds','Alert de-duplication (sec)'],['offline_minutes','Endpoint offline after (min)'],['inactive_hours','Endpoint inactive after (h)'],['retention_days','Retention (days)'],['log_file','Auth log to follow']];
  const ro=can('admin')?'':'disabled';
  P().innerHTML=`<div class="grid g2"><div class="card"><h3>Platform</h3>${F.map(([k,l])=>`<div class="stat"><span>${l}</span><input id="s_${k}" value="${esc(s[k])}" ${ro}></div>`).join('')}<div class="stat"><span>IP geolocation lookup (ip-api.com)</span><select id="s_geo_lookup" ${ro}><option value="1" ${s.geo_lookup==='1'?'selected':''}>On</option><option value="0" ${s.geo_lookup!=='1'?'selected':''}>Off</option></select></div><div class="stat"><span>Enforce blocks with iptables (needs root)</span><select id="s_firewall_enforce" ${ro}><option value="0" ${s.firewall_enforce!=='1'?'selected':''}>Off</option><option value="1" ${s.firewall_enforce==='1'?'selected':''}>On</option></select></div>${can('admin')?'<div class="bar" style="margin-top:14px"><button class="btn" data-a="save">Save</button><button class="btn red" data-a="purge">Purge all alerts &amp; events</button></div>':''}</div>
  <div><div class="card" style="margin-bottom:14px"><h3>Change my password</h3><div class="bar"><input id="pw1" type="password" placeholder="Current"><input id="pw2" type="password" placeholder="New (8+ chars)"><button class="btn" data-a="pw">Update</button></div></div>
  ${can('admin')?`<div class="card"><h3>Ingest API key</h3><p class="mono" id="key" style="word-break:break-all">${esc(s.api_key)}</p><button class="btn ghost" data-a="regen">Regenerate</button><p style="font-size:12px">Send events: <code>curl -X POST ${location.origin}/api/ingest -H "X-API-Key: KEY" -H "Content-Type: application/json" -d '{"source_ip":"1.2.3.4","message":"Failed password for root"}'</code></p></div>`:''}</div></div>`;
  ACT={save:async()=>{const b={};[...F.map(f=>f[0]),'geo_lookup','firewall_enforce'].forEach(k=>b[k]=val('s_'+k));(await api('/api/settings','PUT',b)).ok&&toast('Saved')},
   purge:async()=>{if(confirm('Delete ALL alerts and events?')){await api('/api/admin/purge','POST');toast('Purged')}},
   regen:async()=>{if(confirm('Existing agents will stop working until updated.')){const r=await api('/api/settings/regenerate-key','POST');$('#key').textContent=r.api_key}},
   pw:async()=>{(await api('/api/me/password','POST',{current:val('pw1'),new:val('pw2')})).ok&&toast('Password updated')}}}},
users:{t:['Users','Accounts and roles (admin only)'],async load(){
  if(!can('admin')){P().innerHTML='<div class="card empty">Admin role required.</div>';return}
  P().innerHTML=`<div class="bar"><input id="un" placeholder="Username"><input id="up" type="password" placeholder="Password (8+)"><select id="ur">${opt(['analyst','viewer','admin'])}</select><button class="btn" data-a="add">Add user</button></div><div id="list"></div>`;
  ACT={add:async()=>{const r=await api('/api/users','POST',{username:val('un'),password:$('#up').value,role:$('#ur').value});r.ok&&(PAGES.users.list())},role:async(d,v)=>{await api('/api/users/'+d.id,'PATCH',{role:v});PAGES.users.list()},act:async(d,v)=>{await api('/api/users/'+d.id,'PATCH',{active:v});PAGES.users.list()},
   pw:async d=>{const p=prompt('New password (8+ characters):');if(p)(await api('/api/users/'+d.id,'PATCH',{password:p})).ok&&toast('Password reset')},del:async d=>{if(confirm('Delete user?')){await api('/api/users/'+d.id,'DELETE');PAGES.users.list()}}};PAGES.users.list()},
  async list(){const r=await api('/api/users');$('#list').innerHTML=tbl(['User','Role','Active','Last login','Created',''],r.map(u=>`<tr><td>${esc(u.username)}</td><td><select class="sel" data-c="role" data-id="${u.id}">${opt(['admin','analyst','viewer'],u.role)}</select></td><td><input type="checkbox" data-c="act" data-id="${u.id}" ${u.active?'checked':''}></td><td>${esc(u.last_login||'—')}</td><td>${esc(u.created_at)}</td><td>${btn('Reset password','pw" data-id="'+u.id)}${btn('✕','del" data-id="'+u.id,'red')}</td></tr>`))}}};

/* boot */
api('/api/settings').then(s=>{if(s.org_name)$('#org').textContent=s.org_name.replace(/\s*SOC$/i,'')});
if(page==='dashboard'){clock();setInterval(clock,1000);dash()}else{const c=PAGES[page];head(...c.t);c.load()}
pulse();setInterval(pulse,8000);if(page==='dashboard')setInterval(dash,30000);
let rt;const refresh=w=>{clearTimeout(rt);rt=setTimeout(()=>{if(page==='dashboard')dash();else if(page==='alerts')PAGES.alerts.list();else if(page==='endpoints')PAGES.endpoints.list();else if(page==='network'&&w==='map')api('/api/dashboard').then(d=>drawMap(d.map,d.home,true));pulse()},400)};
if(window.io){const so=io();so.on('alert',a=>{if(RK[a.severity]||a.severity==='Critical'||a.severity==='High')toast(`${a.severity}: ${a.title} (${a.source_ip})`,a.severity)});so.on('refresh',d=>refresh(d&&d.what));so.on('toast',d=>toast(d.text,d.severity))}
else setInterval(()=>refresh(),15000);
