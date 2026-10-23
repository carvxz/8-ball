"use strict";
const $ = id => document.getElementById(id);
const base = String(window.CPIOA_CONFIG?.apiBase || '').replace(/\/$/, '');
const products = { scripts: {name:'Scripts',prefix:'CPIOA'}, '8ball':{name:'8Ball Pool',prefix:'CPIOA8'}, freefire:{name:'Free Fire',prefix:'CPIOAff'} };
const date = seconds => new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short'}).format(new Date(seconds*1000));
let token='', config=null, product='scripts', page=1, total=0, loadingList=0, pendingAction=null, connecting=false;
function message(id,text='',type='') { $(id).textContent=text; $(id).className='message '+type; }
function showAdmin(value) { $('public-view').hidden=value; $('admin-view').hidden=!value; }
function clearSession() {
  token=''; loadingList++; pendingAction=null; $('admin-key').value=''; $('admin-result').hidden=true; $('copy-key').value=''; $('key-rows').replaceChildren();
  for (const id of ['action-dialog','copy-dialog']) if ($(id).open) $(id).close(); showAdmin(false);
}
function openLogin() {
  if (token) { showAdmin(true); loadKeys(); return; }
  message('login-message'); if (!$('login-dialog').open) $('login-dialog').showModal(); $('admin-password').focus();
}
function sessionEnded() { clearSession(); openLogin(); message('login-message','Sua sessão terminou. Entre novamente.','error'); }
async function api(path,options={}) {
  if (!base) throw new Error('Serviço de keys indisponível. Tente novamente em breve.');
  const headers={...options.headers}, controller=new AbortController();
  if (options.body!==undefined) headers['Content-Type']='application/json';
  if (options.admin) headers.Authorization='Bearer '+token;
  const timeout=setTimeout(()=>controller.abort(),12000);
  let response,result;
  try { response=await fetch(base+path,{method:options.method||'GET',headers,body:options.body===undefined?undefined:JSON.stringify(options.body),signal:controller.signal,credentials:'omit',cache:'no-store'}); result=await response.json(); }
  catch { throw new Error('Não foi possível conectar ao serviço. Confira sua conexão e tente novamente.'); }
  finally { clearTimeout(timeout); }
  if (!response.ok || result.ok!==true) {
    if (response.status===401 && options.admin) sessionEnded();
    let text=result.error?.message||'Não foi possível concluir.';
    if (response.status===429) { const retry=Number(response.headers.get('Retry-After')); if (retry>0) text+=` Tente em ${Math.max(1,Math.ceil(retry/60))} min.`; }
    throw Object.assign(new Error(text),{code:result.error?.code});
  }
  return result;
}
async function busy(button,work) {
  if (!button || button.disabled) return;
  button.disabled=true; button.setAttribute('aria-busy','true');
  try { await work(); } finally { button.disabled=false; button.removeAttribute('aria-busy'); }
}
function setConfig(value) {
  config=value; $('service-banner').hidden=!config.accessPaused;
  $('connection').textContent=config.accessPaused?'Acessos temporariamente pausados':'Serviço de keys online';
  $('connection-dot').className='status-dot'+(config.accessPaused?' pending':'');
  $('access-state').textContent=config.accessPaused?'Pausado em Scripts, 8Ball Pool e Free Fire.':'Ativo em Scripts, 8Ball Pool e Free Fire.';
  $('toggle-access').textContent=config.accessPaused?'Reativar todos os acessos':'Pausar todos os acessos';
  $('toggle-access').disabled=false; $('retry-connection').hidden=true;
}
async function refreshConfig() {
  if (connecting) return; connecting=true;
  try { setConfig(await api('/v1/config')); message('service-message'); }
  catch(error) { config=null; $('connection').textContent='Serviço indisponível'; $('connection-dot').className='status-dot offline'; $('retry-connection').hidden=!base; message('service-message',error.message,'error'); }
  finally { connecting=false; }
}
async function copy(value,button,field) {
  const old=button.textContent;
  try { await navigator.clipboard.writeText(value); button.textContent='Copiado ✓'; }
  catch { field.focus(); field.select(); button.textContent='Selecione e copie a key'; }
  setTimeout(()=>{button.textContent=old;},2200);
}
function selectProduct(value) {
  if (!Object.hasOwn(products,value)) return;
  product=value; page=1; loadingList++;
  for (const button of document.querySelectorAll('[data-product]')) { const active=button.dataset.product===value; button.classList.toggle('selected',active); button.setAttribute('aria-pressed',String(active)); }
  $('selected-game-name').textContent=products[value].name;
  $('selected-game-description').textContent=`Keys ${products[value].prefix} exclusivas para ${products[value].name}.`;
  $('selected-game-prefix').textContent=products[value].prefix; $('generate-product').textContent=products[value].name.toUpperCase()+' / '+products[value].prefix;
  $('admin-key').value=''; $('admin-result').hidden=true; $('key-label').value=''; $('search').value=''; $('filter-status').value='all';
  $('key-rows').replaceChildren(); message('admin-generate-message'); if(token) loadKeys();
}
function setDuration() {
  const unit=$('duration-unit').value; $('key-duration').disabled=unit==='never'; $('key-duration').required=unit!=='never';
  $('key-duration').max=unit==='hours'?'8760':'525600';
  $('duration-help').textContent=unit==='never'?'A key não vence automaticamente.':'A contagem começa na geração. De 1 minuto até 1 ano.';
}
function cell(text) { const td=document.createElement('td'); td.textContent=text; return td; }
function rowButton(text,item,work,kind='') {
  const button=document.createElement('button'); button.type='button'; button.className='text-button '+kind;
  button.textContent=text; button.setAttribute('aria-label',text+' '+item.displayKey); button.addEventListener('click',()=>work(button)); return button;
}
function confirmAction(title,label,description,path,body,confirm='Confirmar',danger=false) {
  pendingAction={path,body,product}; $('action-title').textContent=title; $('action-label').textContent=label; $('action-description').textContent=description;
  $('action-confirm').className='button '+(danger?'danger':'primary'); $('action-confirm').textContent=confirm; message('action-message'); $('action-dialog').showModal();
}
async function keyAction(item,action,button) {
  const scope=product;
  await busy(button,async()=>{
    try { await api(`/v1/admin/keys/${item.id}/${action}`,{method:'POST',admin:true,body:{product:scope}}); if(product===scope) await loadKeys(); }
    catch(error) { message('list-message',error.message,'error'); }
  });
}
async function copyKey(item,button) {
  const scope=product;
  await busy(button,async()=>{
    try {
      const result=await api(`/v1/admin/keys/${item.id}/copy`,{method:'POST',admin:true,body:{product:scope}});
      if (scope!==product || !token) return;
      try { await navigator.clipboard.writeText(result.key); message('list-message','Key copiada.','success'); }
      catch { $('copy-key').value=result.key; message('copy-message'); $('copy-dialog').showModal(); $('copy-key').focus(); $('copy-key').select(); }
    } catch(error) { message('list-message',error.message,'error'); }
  });
}
async function loadKeys() {
  if (!token) return;
  const revision=++loadingList, scope=product;
  message('list-message','Carregando keys…');
  try {
    const query=new URLSearchParams({product:scope,search:$('search').value,status:$('filter-status').value,page:String(page)});
    const result=await api('/v1/admin/keys?'+query,{admin:true});
    if (revision!==loadingList || scope!==product || !token) return;
    if (!result.items.length && page>1) { page--; return loadKeys(); }
    total=result.total; setConfig(result.settings); $('key-rows').replaceChildren();
    for (const name of ['total','active','paused','revoked','deleted']) $('stat-'+name).textContent=new Intl.NumberFormat('pt-BR').format(result.stats[name]);
    for (const game of result.products) $('count-'+game.id).textContent=`${game.total} ${game.total===1?'key':'keys'} · ${game.active} ${game.active===1?'ativa':'ativas'}`;
    for (const item of result.items) {
      const row=document.createElement('tr'), name=cell(''), strong=document.createElement('strong'), small=document.createElement('small');
      strong.textContent=item.displayKey; small.textContent=item.label||'Sem identificação'; name.append(strong,small); row.append(name);
      const status=cell(''), badge=document.createElement('span'); badge.className='badge '+item.status;
      badge.textContent={active:'Ativa',paused:'Pausada',expired:'Expirada',revoked:'Revogada',deleted:'Excluída'}[item.status]; status.append(badge); row.append(status);
      row.append(cell(item.expiresAt?date(item.expiresAt):'Sem expiração'));
      const actions=cell(''),group=document.createElement('div'); group.className='row-actions';
      if (item.status==='deleted') {
        group.append(rowButton('Restaurar',item,button=>keyAction(item,'restore',button),'key-toggle'));
      } else {
        if(item.canCopy) group.append(rowButton('Copiar',item,button=>copyKey(item,button)));
        if(['active','paused'].includes(item.status)) group.append(rowButton(item.status==='paused'?'Reativar':'Pausar',item,button=>keyAction(item,item.status==='paused'?'resume':'pause',button),'key-toggle'));
        group.append(rowButton('Excluir',item,()=>confirmAction('Excluir esta key?',products[scope].name+' · '+item.displayKey,
          'A key deixará de funcionar e irá para Excluídas. Você poderá restaurá-la pelo filtro de status.',`/v1/admin/keys/${item.id}/delete`,{product:scope},'Excluir key',true),'revoke-button'));
      }
      actions.append(group); row.append(actions); $('key-rows').append(row);
    }
    if(!result.items.length) { const row=document.createElement('tr'),td=cell($('filter-status').value==='deleted'?'Nenhuma key excluída neste painel.':'Nenhuma key encontrada neste painel.'); td.colSpan=4; td.className='empty'; row.append(td); $('key-rows').append(row); }
    $('page-label').textContent=`Página ${page} de ${Math.max(1,Math.ceil(total/result.pageSize))}`;
    $('previous').disabled=page===1; $('next').disabled=page*result.pageSize>=total; message('list-message');
  } catch(error) { if(revision===loadingList) message('list-message',error.message,'error'); }
}
$('admin-open').addEventListener('click',openLogin); $('login-main').addEventListener('click',openLogin);
$('retry-connection').addEventListener('click',refreshConfig);
$('login-close').addEventListener('click',()=>$('login-dialog').close());
$('login-dialog').addEventListener('close',()=>{$('admin-password').value='';});
$('login-form').addEventListener('submit',event=>{
  event.preventDefault(); busy(event.submitter||event.target.querySelector('button[type=submit]'),async()=>{
    message('login-message','Entrando…'); const password=$('admin-password').value; $('admin-password').value='';
    try { const result=await api('/v1/admin/login',{method:'POST',body:{password}}); token=result.token; page=1; $('login-dialog').close(); showAdmin(true); await loadKeys(); }
    catch(error) { message('login-message',error.message,'error'); }
  });
});
$('logout').addEventListener('click',()=>busy($('logout'),async()=>{
  try { await api('/v1/admin/logout',{method:'POST',admin:true}); } catch { /* The local session is removed in all cases. */ }
  clearSession(); refreshConfig();
}));
for(const button of document.querySelectorAll('[data-product]')) button.addEventListener('click',()=>selectProduct(button.dataset.product));
$('duration-unit').addEventListener('change',setDuration);
$('admin-generate').addEventListener('submit',event=>{
  event.preventDefault(); const scope=product;
  busy(event.submitter||event.target.querySelector('button'),async()=>{
    message('admin-generate-message');
    const unit=$('duration-unit').value, duration=unit==='never'?null:{value:Number($('key-duration').value),unit};
    try {
      const result=await api('/v1/admin/keys',{method:'POST',admin:true,body:{product:scope,label:$('key-label').value,duration}});
      if(scope!==product || !token) return;
      $('admin-key').value=result.key; $('admin-result').hidden=false;
      $('generated-expiry').textContent=result.license.expiresAt?'Válida até '+date(result.license.expiresAt):'Sem prazo de validade';
      message('admin-generate-message','Key de '+products[scope].name+' gerada.','success'); page=1; await loadKeys();
    } catch(error) { if(scope===product) message('admin-generate-message',error.message,'error'); }
  });
});
$('admin-copy').addEventListener('click',()=>copy($('admin-key').value,$('admin-copy'),$('admin-key')));
$('admin-key').addEventListener('click',event=>event.target.select());
$('filter-form').addEventListener('submit',event=>{event.preventDefault();page=1;loadKeys();});
$('filter-status').addEventListener('change',()=>{page=1;loadKeys();});
$('refresh').addEventListener('click',loadKeys);
$('previous').addEventListener('click',()=>{if(page>1){page--;loadKeys();}});
$('next').addEventListener('click',()=>{page++;loadKeys();});
$('toggle-access').addEventListener('click',()=>{
  if(!config) return;
  confirmAction(config.accessPaused?'Reativar todos os acessos?':'Pausar todos os acessos?','Scripts, 8Ball Pool e Free Fire',
    config.accessPaused?'Keys ativas voltarão a liberar acesso. Keys pausadas individualmente continuam bloqueadas.':'Todas as keys serão bloqueadas na próxima validação. Você poderá reativar o serviço quando quiser.',
    '/v1/admin/settings',{accessPaused:!config.accessPaused});
});
$('action-cancel').addEventListener('click',()=>$('action-dialog').close());
$('action-dialog').addEventListener('close',()=>{pendingAction=null;});
$('action-confirm').addEventListener('click',()=>busy($('action-confirm'),async()=>{
  if(!pendingAction) return;
  const action=pendingAction;
  try { const result=await api(action.path,{method:'POST',admin:true,body:action.body}); if(result.accessPaused!==undefined)setConfig(result); $('action-dialog').close(); await loadKeys(); }
  catch(error) { message('action-message',error.message,'error'); }
}));
$('copy-close').addEventListener('click',()=>$('copy-dialog').close());
$('copy-dialog').addEventListener('close',()=>{$('copy-key').value='';});
$('copy-again').addEventListener('click',()=>copy($('copy-key').value,$('copy-again'),$('copy-key')));
document.addEventListener('visibilitychange',()=>{if(!document.hidden){if(token)loadKeys();else refreshConfig();}});
setInterval(()=>{if(base && !document.hidden && !token)refreshConfig();},60000);
setDuration(); refreshConfig();
