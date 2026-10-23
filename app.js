'use strict';
const $ = id => document.getElementById(id);
const base = String(window.CPIOA_CONFIG?.apiBase || '').replace(/\/$/, '');
const keyPattern = /^CPIOA(?:-[0-9A-HJKMNP-TV-Z]{8}){4}$/;
const storageKey = 'cpioa-current-key:' + location.pathname;
const date = seconds => new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(seconds * 1000));
let token = '', config = null, page = 1, total = 0, loadingList = 0;
let widgetId = null, challengeToken = '', pendingAction = null, connecting = false;

function message(id, text = '', type = '') {
  $(id).textContent = text;
  $(id).className = 'message ' + type;
}
function showPublic() {
  $('public-view').hidden = false; $('admin-view').hidden = true; $('como-usar').hidden = false;
}
function showAdmin() {
  $('public-view').hidden = true; $('admin-view').hidden = false; $('como-usar').hidden = true;
}
function clearSession() {
  token = ''; loadingList++; pendingAction = null;
  $('admin-key').value = ''; $('admin-result').hidden = true; $('key-rows').replaceChildren();
  if ($('action-dialog').open) $('action-dialog').close();
  showPublic();
}
function sessionEnded() {
  clearSession();
  message('login-message', 'Sua sessão terminou. Entre novamente.', 'error');
  if (!$('login-dialog').open) $('login-dialog').showModal();
}
async function api(path, options = {}) {
  if (!base) throw new Error('O serviço de keys está sendo preparado. Tente novamente em breve.');
  const headers = { ...options.headers }, controller = new AbortController();
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (options.admin) headers.Authorization = 'Bearer ' + token;
  const timeout = setTimeout(() => controller.abort(), 12000);
  let response, result;
  try {
    response = await fetch(base + path, { method: options.method || 'GET', headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal, credentials: 'omit', cache: 'no-store' });
    result = await response.json();
  } catch { throw new Error('Não foi possível conectar ao serviço. Confira sua conexão e tente novamente.'); }
  finally { clearTimeout(timeout); }
  if (!response.ok || result.ok !== true) {
    if (response.status === 401 && options.admin) sessionEnded();
    let text = result.error?.message || 'Não foi possível concluir. Tente novamente.';
    if (response.status === 429) {
      const retry = Number(response.headers.get('Retry-After'));
      if (retry > 0) text += ` Tente em ${Math.max(1, Math.ceil(retry / 60))} min.`;
    }
    throw Object.assign(new Error(text), { code: result.error?.code });
  }
  return result;
}
async function busy(button, work) {
  if (!button || button.disabled) return;
  button.disabled = true; button.setAttribute('aria-busy', 'true');
  try { await work(); }
  finally {
    button.disabled = false; button.removeAttribute('aria-busy');
    if (button === $('generate')) button.disabled = !config?.publicGeneration;
  }
}
async function copy(value, button, field) {
  const old = button.textContent;
  try { await navigator.clipboard.writeText(value); button.textContent = 'Copiado ✓'; }
  catch { field.focus(); field.select(); button.textContent = 'Selecione e copie a key'; }
  setTimeout(() => { button.textContent = old; }, 2200);
}
function displayKey(result, save = true) {
  $('generated').hidden = false; $('generated-key').value = result.key;
  $('expiry').textContent = result.license.expiresAt ? 'Válida até ' + date(result.license.expiresAt) : 'Sem prazo de validade';
  $('generate').firstElementChild.textContent = 'Gerar outra key';
  if (save) try { sessionStorage.setItem(storageKey, JSON.stringify(result)); } catch { /* Storage may be disabled. */ }
}
function setTab(verify) {
  $('generate-view').hidden = verify; $('verify-view').hidden = !verify;
  for (const [id, active] of [['tab-generate', !verify], ['tab-verify', verify]]) {
    $(id).classList.toggle('active', active); $(id).setAttribute('aria-pressed', String(active));
  }
}
function setConfig(value) {
  config = value;
  $('duration').textContent = config.keyHours === null ? 'Sem expiração' : config.keyHours % 24 === 0
    ? `${config.keyHours / 24} ${config.keyHours === 24 ? 'dia' : 'dias'}` : `${config.keyHours} horas`;
  $('service-banner').hidden = !config.accessPaused;
  if (!$('generate').hasAttribute('aria-busy')) $('generate').disabled = !config.publicGeneration;
  $('connection').textContent = config.accessPaused ? 'Acesso temporariamente pausado'
    : config.publicGeneration ? 'Pronto para gerar seu acesso' : 'Geração temporariamente pausada';
  $('connection-dot').className = 'status-dot' + (config.accessPaused || !config.publicGeneration ? ' pending' : '');
  $('access-state').textContent = config.accessPaused ? 'Pausado. Nenhuma key libera acesso.' : 'Ativo. Keys válidas liberam acesso.';
  $('generation-state').textContent = config.accessPaused ? 'Indisponível durante a pausa geral.'
    : config.publicGeneration ? 'Aberta para os visitantes.' : 'Pausada. As keys existentes continuam válidas.';
  $('toggle-access').textContent = config.accessPaused ? 'Reativar todos os acessos' : 'Pausar todos os acessos';
  $('toggle-generation').textContent = config.generationPaused ? 'Reabrir geração' : 'Pausar geração';
  $('toggle-access').disabled = false; $('toggle-generation').disabled = false;
  $('retry-connection').hidden = true;
}
async function refreshConfig() {
  if (connecting) return;
  connecting = true;
  try {
    const value = await api('/v1/config');
    if (value.turnstileSiteKey && widgetId === null) await turnstile(value.turnstileSiteKey);
    setConfig(value);
    message('generate-message', value.accessPaused ? 'O acesso está pausado. Guarde sua key para usar quando o serviço voltar.'
      : !value.publicGeneration ? 'A geração de keys está pausada. Volte mais tarde.' : '');
  } catch (error) {
    config = null; $('generate').disabled = true;
    $('connection').textContent = base ? 'Serviço indisponível' : 'Serviço em configuração';
    $('connection-dot').className = 'status-dot offline'; $('retry-connection').hidden = !base;
    message('generate-message', error.message, 'error');
  } finally { connecting = false; }
}

$('tab-generate').addEventListener('click', () => setTab(false));
$('tab-verify').addEventListener('click', () => setTab(true));
$('retry-connection').addEventListener('click', refreshConfig);
$('generate').addEventListener('click', () => busy($('generate'), async () => {
  message('generate-message', 'Gerando seu acesso…');
  try {
    if (config?.turnstileSiteKey && !challengeToken) throw new Error('Conclua a verificação acima para continuar.');
    const result = await api('/v1/keys', { method: 'POST', body: { turnstileToken: challengeToken } });
    displayKey(result); message('generate-message', 'Pronto. Copie e guarde sua key.', 'success');
  } catch (error) {
    if (error.code === 'GENERATION_CLOSED') await refreshConfig();
    message('generate-message', error.message, 'error');
  } finally {
    if (widgetId !== null) { window.turnstile.reset(widgetId); challengeToken = ''; }
  }
}));
$('copy').addEventListener('click', () => copy($('generated-key').value, $('copy'), $('generated-key')));
$('generated-key').addEventListener('click', event => event.target.select());
$('verify-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter || event.target.querySelector('button'), async () => {
    message('verify-message', 'Verificando…');
    try {
      const result = await api('/v1/verify', { method: 'POST', body: { key: $('verify-key').value } });
      message('verify-message', result.license.expiresAt ? 'Key ativa até ' + date(result.license.expiresAt) + '.' : 'Key ativa, sem prazo de validade.', 'success');
    } catch (error) { message('verify-message', error.message, 'error'); }
  });
});
$('admin-open').addEventListener('click', () => {
  if (token) { showAdmin(); loadKeys(); }
  else { message('login-message'); $('login-dialog').showModal(); $('admin-password').focus(); }
});
$('login-close').addEventListener('click', () => $('login-dialog').close());
$('login-dialog').addEventListener('close', () => { $('admin-password').value = ''; });
$('login-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter || event.target.querySelector('button[type=submit], button.primary'), async () => {
    message('login-message', 'Entrando…');
    const password = $('admin-password').value; $('admin-password').value = '';
    try {
      const result = await api('/v1/admin/login', { method: 'POST', body: { password } });
      token = result.token; page = 1; $('login-dialog').close(); message('login-message'); showAdmin(); await loadKeys();
    } catch (error) { message('login-message', error.message, 'error'); }
  });
});
$('logout').addEventListener('click', () => busy($('logout'), async () => {
  try { await api('/v1/admin/logout', { method: 'POST', admin: true }); } catch { /* Local session is always removed. */ }
  clearSession(); await refreshConfig();
}));
$('admin-generate').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter || event.target.querySelector('button'), async () => {
    message('admin-generate-message');
    try {
      const value = $('key-hours').value;
      const result = await api('/v1/admin/keys', { method: 'POST', admin: true,
        body: { label: $('key-label').value, hours: value === 'never' ? null : Number(value) } });
      $('admin-key').value = result.key; $('admin-result').hidden = false; page = 1; await loadKeys();
    } catch (error) { message('admin-generate-message', error.message, 'error'); }
  });
});
$('admin-copy').addEventListener('click', () => copy($('admin-key').value, $('admin-copy'), $('admin-key')));
function cell(text) { const td = document.createElement('td'); td.textContent = text; return td; }
function confirmAction(title, label, description, path, body, danger = false) {
  pendingAction = { path, body };
  $('action-title').textContent = title; $('action-label').textContent = label; $('action-description').textContent = description;
  $('action-confirm').className = 'button ' + (danger ? 'danger' : 'primary');
  $('action-confirm').textContent = danger ? 'Revogar definitivamente' : 'Confirmar';
  message('action-message'); $('action-dialog').showModal();
}
async function toggleKey(item, button) {
  await busy(button, async () => {
    try {
      await api(`/v1/admin/keys/${item.id}/${item.status === 'paused' ? 'resume' : 'pause'}`, { method: 'POST', admin: true });
      await loadKeys();
    } catch (error) { message('list-message', error.message, 'error'); }
  });
}
async function loadKeys() {
  const revision = ++loadingList;
  message('list-message', 'Carregando keys…');
  try {
    const query = new URLSearchParams({ search: $('search').value, status: $('filter-status').value, page: String(page) });
    const result = await api('/v1/admin/keys?' + query, { admin: true });
    if (revision !== loadingList || !token) return;
    total = result.total; setConfig(result.settings); $('key-rows').replaceChildren();
    for (const name of ['total', 'active', 'paused', 'revoked']) $('stat-' + name).textContent = new Intl.NumberFormat('pt-BR').format(result.stats[name]);
    for (const item of result.items) {
      const row = document.createElement('tr'), name = cell(''), strong = document.createElement('strong'), small = document.createElement('small');
      strong.textContent = item.displayKey; small.textContent = item.label || 'Sem identificação'; name.append(strong, small); row.append(name);
      const status = cell(''), badge = document.createElement('span'); badge.className = 'badge ' + item.status;
      badge.textContent = { active: 'Ativa', paused: 'Pausada', expired: 'Expirada', revoked: 'Revogada' }[item.status]; status.append(badge); row.append(status);
      row.append(cell(item.expiresAt ? date(item.expiresAt) : 'Sem expiração'));
      const actions = cell(''), group = document.createElement('div'); group.className = 'row-actions';
      if (['active', 'paused'].includes(item.status)) {
        const button = document.createElement('button'); button.className = 'text-button key-toggle';
        button.textContent = item.status === 'paused' ? 'Reativar' : 'Pausar'; button.setAttribute('aria-label', button.textContent + ' ' + item.displayKey);
        button.addEventListener('click', () => toggleKey(item, button)); group.append(button);
      }
      if (item.status !== 'revoked') {
        const button = document.createElement('button'); button.className = 'text-button revoke-button'; button.textContent = 'Revogar';
        button.setAttribute('aria-label', 'Revogar ' + item.displayKey);
        button.addEventListener('click', () => confirmAction('Revogar esta key?', item.displayKey + (item.label ? ' · ' + item.label : ''),
          'Essa key deixará de funcionar e não poderá ser reativada. Para bloquear temporariamente, use Pausar.', `/v1/admin/keys/${item.id}/revoke`, undefined, true));
        group.append(button);
      }
      actions.append(group); row.append(actions); $('key-rows').append(row);
    }
    if (!result.items.length) {
      const row = document.createElement('tr'), td = cell('Nenhuma key encontrada.'); td.colSpan = 4; td.className = 'empty'; row.append(td); $('key-rows').append(row);
    }
    $('page-label').textContent = `Página ${page} de ${Math.max(1, Math.ceil(total / result.pageSize))}`;
    $('previous').disabled = page === 1; $('next').disabled = page * result.pageSize >= total;
    message('list-message');
  } catch (error) { if (revision === loadingList) message('list-message', error.message, 'error'); }
}
$('filter-form').addEventListener('submit', event => { event.preventDefault(); page = 1; loadKeys(); });
$('refresh').addEventListener('click', loadKeys);
$('previous').addEventListener('click', () => { if (page > 1) { page--; loadKeys(); } });
$('next').addEventListener('click', () => { page++; loadKeys(); });
$('toggle-access').addEventListener('click', () => {
  if (!config) return;
  confirmAction(config.accessPaused ? 'Reativar todos os acessos?' : 'Pausar todos os acessos?', 'Controle geral do Cpioa',
    config.accessPaused ? 'As keys ativas voltarão a liberar acesso. Keys pausadas individualmente continuam bloqueadas.'
      : 'Todas as keys deixarão de liberar acesso na próxima validação. Você poderá reativar o serviço quando quiser.',
    '/v1/admin/settings', { accessPaused: !config.accessPaused });
});
$('toggle-generation').addEventListener('click', () => busy($('toggle-generation'), async () => {
  if (!config) return;
  try {
    const result = await api('/v1/admin/settings', { method: 'POST', admin: true, body: { generationPaused: !config.generationPaused } });
    setConfig(result); message('settings-message', 'Geração pública atualizada.', 'success');
  } catch (error) { message('settings-message', error.message, 'error'); }
}));
$('action-cancel').addEventListener('click', () => $('action-dialog').close());
$('action-dialog').addEventListener('close', () => { pendingAction = null; });
$('action-confirm').addEventListener('click', () => busy($('action-confirm'), async () => {
  if (!pendingAction) return;
  try {
    const action = pendingAction;
    await api(action.path, { method: 'POST', admin: true, body: action.body });
    $('action-dialog').close(); await loadKeys();
  } catch (error) { message('action-message', error.message, 'error'); }
}));
async function turnstile(siteKey) {
  if (!window.turnstile) await new Promise((resolve, reject) => {
    const script = document.createElement('script'); script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.onload = resolve; script.onerror = () => { script.remove(); reject(new Error('Não foi possível abrir a verificação. Tente reconectar.')); };
    document.head.append(script);
  });
  await new Promise(resolve => window.turnstile.ready(resolve));
  widgetId = window.turnstile.render('#challenge', { sitekey: siteKey, theme: 'dark', size: 'flexible', action: 'generate',
    callback: value => { challengeToken = value; }, 'expired-callback': () => { challengeToken = ''; },
    'error-callback': () => { challengeToken = ''; message('generate-message', 'Refaça a verificação para continuar.', 'error'); } });
}
(async () => {
  await refreshConfig();
  try {
    const saved = JSON.parse(sessionStorage.getItem(storageKey));
    if (keyPattern.test(saved?.key) && saved.license && (saved.license.expiresAt === null || saved.license.expiresAt > Date.now() / 1000)) {
      displayKey(saved, false);
      if (config) {
        try { await api('/v1/verify', { method: 'POST', body: { key: saved.key } }); }
        catch (error) { message('generate-message', error.message, 'error'); }
      }
    }
  } catch { /* No usable key saved in this tab. */ }
})();
setInterval(() => { if (base && !document.hidden && !token) refreshConfig(); }, 60000);
document.addEventListener('visibilitychange', () => { if (base && !document.hidden) { if (token) loadKeys(); else refreshConfig(); } });
