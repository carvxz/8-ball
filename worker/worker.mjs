// Cpioa Keys — Cloudflare Worker ESM
const utf8 = new TextEncoder();
const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PRODUCTS = Object.freeze({
  scripts: { id: 'scripts', name: 'Scripts', prefix: 'CPIOA' },
  '8ball': { id: '8ball', name: '8Ball Pool', prefix: 'CPIOA8' },
  freefire: { id: 'freefire', name: 'Free Fire', prefix: 'CPIOAff' }
});
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async value => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(value))));
const randomToken = () => hex(crypto.getRandomValues(new Uint8Array(32)));
function newKey(product) {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, buffer = 0, result = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; result += alphabet[(buffer >>> bits) & 31]; }
  }
  return PRODUCTS[product].prefix + '-' + result.match(/.{8}/g).join('-');
}
function normalizeKey(value) {
  if (typeof value !== 'string' || value.length > 100) return null;
  const compact = value.toUpperCase().replace(/[\s\u00a0-]/g, '');
  for (const product of Object.values(PRODUCTS)) {
    const prefix = product.prefix.toUpperCase();
    if (compact.length === prefix.length + 32 && compact.startsWith(prefix) && /^[0-9A-HJKMNP-TV-Z]{32}$/.test(compact.slice(prefix.length))) {
      return product.prefix + '-' + compact.slice(prefix.length).match(/.{8}/g).join('-');
    }
  }
  return null;
}
function productOf(key) {
  return Object.values(PRODUCTS).find(product => key.startsWith(product.prefix + '-'))?.id;
}
function requireProduct(value) {
  if (typeof value !== 'string' || !Object.hasOwn(PRODUCTS, value)) fail(400, 'PRODUCT_REQUIRED', 'Escolha Scripts, 8Ball Pool ou Free Fire.');
  return value;
}
const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256));
}
async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 256) throw new Error('Use uma senha de 16 a 256 caracteres.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2-sha256$100000$${toBase64(salt)}$${toBase64(await derive(password, salt, 100000))}`;
}
function validPasswordHash(value) {
  return typeof value === 'string' && /^pbkdf2-sha256\$100000\$[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=$/.test(value);
}
async function checkPassword(password, stored) {
  if (!validPasswordHash(stored) || typeof password !== 'string' || password.length > 256) return false;
  const [, iterations, salt, encoded] = stored.split('$');
  const expected = fromBase64(encoded), actual = await derive(password, fromBase64(salt), Number(iterations));
  if (typeof crypto.subtle.timingSafeEqual === 'function') return crypto.subtle.timingSafeEqual(expected, actual);
  let mismatch = expected.length ^ actual.length;
  for (let i = 0; i < expected.length; i++) mismatch |= expected[i] ^ actual[i];
  return mismatch === 0;
}


const SESSION_SECONDS = 7200;
const PAGE_SIZE = 20;
class ApiError extends Error {
  constructor(status, code, message, retryAfter) { super(message); Object.assign(this, { status, code, retryAfter }); }
}
const fail = (status, code, message, retryAfter) => { throw new ApiError(status, code, message, retryAfter); };
const nowSeconds = () => Math.floor(Date.now() / 1000);
const json = (body, status = 200) => Response.json(body, { status });
function origins(env) { return String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean); }
function secureResponse(response, origin, env) {
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Vary', 'Origin');
  if (origin && origins(env).includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    headers.set('Access-Control-Expose-Headers', 'Retry-After');
    headers.set('Access-Control-Max-Age', '600');
  }
  return new Response(response.body, { status: response.status, headers });
}
async function bodyJson(request) {
  if (!/^application\/json(?:;|$)/i.test(request.headers.get('Content-Type') || '')) fail(415, 'JSON_REQUIRED', 'Envie os dados em JSON.');
  if (Number(request.headers.get('Content-Length')) > 4096) fail(413, 'BODY_TOO_LARGE', 'Dados muito grandes.');
  const reader = request.body?.getReader();
  if (!reader) fail(400, 'INVALID_JSON', 'Dados inválidos.');
  const chunks = []; let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 4096) { await reader.cancel(); fail(413, 'BODY_TOO_LARGE', 'Dados muito grandes.'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const buffer = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.length; }
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer)); }
  catch { fail(400, 'INVALID_JSON', 'Dados inválidos.'); }
  if (!value || Array.isArray(value) || typeof value !== 'object') fail(400, 'INVALID_JSON', 'Dados inválidos.');
  return value;
}
async function rateLimit(request, env, scope, limit, duration, now, shared = false) {
  // Cloudflare provides this header; arbitrary forwarded headers are never trusted.
  const ip = shared ? 'global' : request.headers.get('CF-Connecting-IP') || 'local';
  const bucket = scope + ':' + await sha256(env.ADMIN_PASSWORD_HASH + ':' + ip);
  const start = Math.floor(now / duration) * duration;
  const row = await env.DB.prepare(`INSERT INTO rate_limits(bucket, window_start, reset_at, hits) VALUES (?, ?, ?, 1)
    ON CONFLICT(bucket) DO UPDATE SET hits = CASE WHEN window_start = excluded.window_start THEN hits + 1 ELSE 1 END,
      window_start = excluded.window_start, reset_at = excluded.reset_at RETURNING hits`).bind(bucket, start, start + duration).first();
  if (row.hits > limit) fail(429, 'RATE_LIMITED', 'Muitas tentativas. Aguarde um pouco.', start + duration - now);
}
async function admin(request, env, now) {
  const token = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.get('Authorization') || '')?.[1];
  if (!token) fail(401, 'AUTH_REQUIRED', 'Entre no painel para continuar.');
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare('SELECT expires_at, password_version FROM admin_sessions WHERE token_hash = ?').bind(tokenHash).first();
  if (!row || row.expires_at <= now || row.password_version !== await sha256(env.ADMIN_PASSWORD_HASH)) {
    fail(401, 'SESSION_EXPIRED', 'Sua sessão terminou. Entre novamente.');
  }
  return tokenHash;
}
function licenseView(row, now) {
  const previousStatus = row.revoked_at !== null ? 'revoked' : row.expires_at !== null && row.expires_at <= now ? 'expired' : row.paused_at !== null ? 'paused' : 'active';
  return { id: row.id, product: row.product, displayKey: row.display_key, label: row.label,
    createdAt: row.created_at, expiresAt: row.expires_at, pausedAt: row.paused_at, revokedAt: row.revoked_at,
    deletedAt: row.deleted_at, canCopy: Boolean(row.key_ciphertext) && row.deleted_at === null,
    status: row.deleted_at !== null ? 'deleted' : previousStatus, previousStatus };
}
const schemaPromises = new WeakMap();
async function ensureSchema(env) {
  if (!env.DB) return;
  let promise = schemaPromises.get(env.DB);
  if (!promise) {
    promise = (async () => {
      const columns = new Set((await env.DB.prepare('PRAGMA table_info(licenses)').all()).results.map(row => row.name));
      if (!columns.has('id')) fail(503, 'NOT_CONFIGURED', 'Banco de keys não configurado.');
      const migrateLegacy = !columns.has('product');
      const changes = [];
      if (migrateLegacy) changes.push(env.DB.prepare("ALTER TABLE licenses ADD COLUMN product TEXT NOT NULL DEFAULT 'scripts' CHECK (product IN ('scripts', '8ball', 'freefire'))"));
      if (!columns.has('key_ciphertext')) changes.push(env.DB.prepare('ALTER TABLE licenses ADD COLUMN key_ciphertext TEXT'));
      if (!columns.has('deleted_at')) changes.push(env.DB.prepare('ALTER TABLE licenses ADD COLUMN deleted_at INTEGER'));
      if (migrateLegacy) changes.push(env.DB.prepare('UPDATE licenses SET deleted_at = ?, updated_at = ? WHERE deleted_at IS NULL').bind(nowSeconds(), nowSeconds()));
      if (changes.length) {
        try { await env.DB.batch(changes); }
        catch (error) {
          // Another isolate may have completed the same atomic migration first.
          if (!/duplicate column name/i.test(String(error?.message))) throw error;
          const complete = new Set((await env.DB.prepare('PRAGMA table_info(licenses)').all()).results.map(row => row.name));
          if (!['product','key_ciphertext','deleted_at'].every(name => complete.has(name))) throw error;
        }
      }
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS licenses_product_created ON licenses(product, deleted_at, created_at DESC)').run();
    })();
    schemaPromises.set(env.DB, promise);
    promise.catch(() => schemaPromises.delete(env.DB));
  }
  await promise;
}
async function storageKey(env) {
  const material = await crypto.subtle.importKey('raw', utf8.encode(env.KEY_STORAGE_SECRET || env.ADMIN_PASSWORD_HASH), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: utf8.encode('cpioa-keys-storage-v1'), info: utf8.encode('admin-copy-only') },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
}
async function encryptKey(env, key, id, product) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(id + ':' + product) }, await storageKey(env), utf8.encode(key));
  return 'v1.' + toBase64(iv) + '.' + toBase64(new Uint8Array(encrypted));
}
async function decryptKey(env, row) {
  if (!row.key_ciphertext) fail(409, 'KEY_COPY_UNAVAILABLE', 'O código completo desta key antiga não está disponível. Gere uma nova.');
  try {
    const [version, iv, encrypted] = row.key_ciphertext.split('.');
    if (version !== 'v1') throw new Error();
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(iv), additionalData: utf8.encode(row.id + ':' + row.product) }, await storageKey(env), fromBase64(encrypted));
    const key = new TextDecoder().decode(plain);
    if (normalizeKey(key) !== key || productOf(key) !== row.product || await sha256(key) !== row.key_hash) throw new Error();
    return key;
  } catch {
    fail(409, 'KEY_COPY_UNAVAILABLE', 'Não foi possível recuperar o código. A validação da key continua funcionando.');
  }
}
function durationSeconds(body) {
  if (Object.hasOwn(body, 'duration')) {
    if (body.duration === null) return null;
    const duration = body.duration;
    if (!duration || typeof duration !== 'object' || !Number.isInteger(duration.value) || !['minutes','hours'].includes(duration.unit)) fail(400, 'DURATION_INVALID', 'Informe uma quantidade inteira de minutos ou horas.');
    const seconds = duration.value * (duration.unit === 'minutes' ? 60 : 3600);
    if (seconds < 60 || seconds > 31536000) fail(400, 'DURATION_INVALID', 'A validade deve ficar entre 1 minuto e 1 ano.');
    return seconds;
  }
  if (body.hours === null) return null;
  if (Number.isInteger(body.hours) && body.hours >= 1 && body.hours <= 8760) return body.hours * 3600;
  fail(400, 'DURATION_INVALID', 'Escolha minutos, horas ou sem expiração.');
}
async function gameStats(env, now) {
  const rows = (await env.DB.prepare(`SELECT product, COUNT(*) AS total,
    COALESCE(SUM(revoked_at IS NULL AND paused_at IS NULL AND (expires_at IS NULL OR expires_at > ?)),0) AS active
    FROM licenses WHERE deleted_at IS NULL GROUP BY product`).bind(now).all()).results;
  return Object.values(PRODUCTS).map(product => ({ ...product, ...(rows.find(row => row.product === product.id) || { total: 0, active: 0 }) }));
}
async function settings(env) {
  const row = await env.DB.prepare('SELECT access_paused, generation_paused, updated_at FROM system_settings WHERE id = 1').first();
  if (!row) fail(503, 'NOT_CONFIGURED', 'O serviço ainda está sendo configurado.');
  return { accessPaused: Boolean(row.access_paused), generationPaused: Boolean(row.generation_paused), updatedAt: row.updated_at };
}
async function publicConfig(env) {
  const value = env.PUBLIC_KEY_HOURS ?? 'never';
  const hours = value === 'never' ? null : Number(value);
  if (hours !== null && (!Number.isInteger(hours) || hours < 1 || hours > 8760)) fail(503, 'NOT_CONFIGURED', 'Validade do serviço não configurada.');
  const checkAfterSeconds = Number(env.CHECK_AFTER_SECONDS || 60);
  if (!Number.isInteger(checkAfterSeconds) || checkAfterSeconds < 15 || checkAfterSeconds > 3600) fail(503, 'NOT_CONFIGURED', 'Intervalo do serviço não configurado.');
  const siteKey = String(env.TURNSTILE_SITE_KEY || '');
  if (Boolean(siteKey) !== Boolean(env.TURNSTILE_SECRET_KEY)) fail(503, 'NOT_CONFIGURED', 'Verificação do serviço não configurada.');
  const state = await settings(env);
  return { ...state, publicGeneration: false, products: Object.values(PRODUCTS),
    keyHours: hours, checkAfterSeconds, turnstileSiteKey: siteKey };
}
async function issueKey(env, product, label, seconds, now) {
  const key = newKey(product), id = crypto.randomUUID(), expiresAt = seconds === null ? null : now + seconds;
  const displayKey = key.slice(0, PRODUCTS[product].prefix.length + 6) + '…' + key.slice(-6);
  const encrypted = await encryptKey(env, key, id, product);
  await env.DB.prepare(`INSERT INTO licenses(id, key_hash, display_key, label, created_at, expires_at, product, key_ciphertext)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, await sha256(key), displayKey, label, now, expiresAt, product, encrypted).run();
  return json({ ok: true, key, license: { id, product, displayKey, label, createdAt: now, expiresAt, status: 'active', canCopy: true } }, 201);
}
async function route(request, env) {
  const url = new URL(request.url), now = nowSeconds();
  const origin = request.headers.get('Origin');
  if (origin && !origins(env).includes(origin)) fail(403, 'ORIGIN_DENIED', 'Este endereço não tem acesso à API.');
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) fail(400, 'HTTPS_REQUIRED', 'Use uma conexão HTTPS.');
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (url.pathname === '/v1/health' && request.method === 'GET') {
    if (!env.DB || !validPasswordHash(env.ADMIN_PASSWORD_HASH)) fail(503, 'NOT_CONFIGURED', 'O serviço ainda está sendo configurado.');
    await env.DB.prepare('SELECT id FROM licenses LIMIT 1').first();
    const config = await publicConfig(env);
    return json({ ok: true, service: 'cpioa-keys', accessPaused: config.accessPaused, publicGeneration: config.publicGeneration });
  }
  if (!env.DB || !validPasswordHash(env.ADMIN_PASSWORD_HASH)) fail(503, 'NOT_CONFIGURED', 'O serviço ainda está sendo configurado.');
  if (url.pathname === '/v1/config' && request.method === 'GET') return json({ ok: true, ...await publicConfig(env) });
if (url.pathname === '/v1/keys' && request.method === 'POST') fail(403, 'GENERATION_CLOSED', 'A geração de keys é exclusiva do administrador.');
  if (url.pathname === '/v1/admin/login' && request.method === 'POST') {
    await rateLimit(request, env, 'login', 5, 900, now);
    const body = await bodyJson(request);
    if (!await checkPassword(body.password, env.ADMIN_PASSWORD_HASH)) fail(401, 'LOGIN_FAILED', 'Senha incorreta.');
    const token = randomToken(), expiresAt = now + SESSION_SECONDS;
    await env.DB.prepare('INSERT INTO admin_sessions(token_hash, password_version, expires_at) VALUES (?, ?, ?)')
      .bind(await sha256(token), await sha256(env.ADMIN_PASSWORD_HASH), expiresAt).run();
    return json({ ok: true, token, expiresAt });
  }
if (url.pathname === '/v1/verify' && request.method === 'POST') {
    const body = await bodyJson(request), key = normalizeKey(body.key);
    if (!key) { await rateLimit(request, env, 'verify-invalid', 30, 60, now); fail(401, 'KEY_INVALID', 'Key inválida.'); }
    if (typeof body.product !== 'string' || !Object.hasOwn(PRODUCTS, body.product)) fail(400, 'APP_REQUIRED', 'Atualize o aplicativo para validar a key deste jogo.');
    const product = body.product;
    if (productOf(key) !== product) fail(401, 'KEY_WRONG_APP', 'Esta key pertence a outro painel.');
    const config = await publicConfig(env);
    if (config.accessPaused) fail(403, 'ACCESS_PAUSED', 'O acesso ao Cpioa está temporariamente pausado.');
    const row = await env.DB.prepare('SELECT id, expires_at, revoked_at, paused_at, deleted_at, product FROM licenses WHERE key_hash = ?').bind(await sha256(key)).first();
    if (!row) { await rateLimit(request, env, 'verify-invalid', 30, 60, now); fail(401, 'KEY_INVALID', 'Key inválida.'); }
    if (row.product !== product) fail(401, 'KEY_WRONG_APP', 'Esta key pertence a outro painel.');
    if (row.deleted_at !== null) fail(401, 'KEY_DELETED', 'Esta key foi excluída.');
    if (row.revoked_at !== null) fail(401, 'KEY_REVOKED', 'Esta key foi revogada.');
    if (row.expires_at !== null && row.expires_at <= now) fail(401, 'KEY_EXPIRED', 'Esta key expirou.');
    if (row.paused_at !== null) fail(403, 'KEY_PAUSED', 'Esta key está pausada.');
    return json({ ok: true, license: { id: row.id, product, expiresAt: row.expires_at, status: 'active' }, serverTime: now,
      checkAfterSeconds: row.expires_at === null ? config.checkAfterSeconds : Math.max(1, Math.min(config.checkAfterSeconds, row.expires_at - now)) });
  }
  if (!url.pathname.startsWith('/v1/admin/')) fail(404, 'NOT_FOUND', 'Endereço não encontrado.');
  await rateLimit(request, env, 'admin', 120, 60, now);
  const sessionHash = await admin(request, env, now);
  if (url.pathname === '/v1/admin/logout' && request.method === 'POST') {
    await env.DB.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').bind(sessionHash).run();
    return json({ ok: true });
  }
  if (url.pathname === '/v1/admin/settings' && request.method === 'GET') return json({ ok: true, ...await publicConfig(env) });
  if (url.pathname === '/v1/admin/settings' && request.method === 'POST') {
    const body = await bodyJson(request), fields = Object.keys(body);
    if (!fields.length || fields.some(field => !['accessPaused', 'generationPaused'].includes(field) || typeof body[field] !== 'boolean')) fail(400, 'SETTINGS_INVALID', 'Configuração inválida.');
    const columns = fields.map(field => field === 'accessPaused' ? 'access_paused' : 'generation_paused');
    await env.DB.prepare('UPDATE system_settings SET ' + columns.map(column => column + ' = ?').join(', ') + ', updated_at = ? WHERE id = 1')
      .bind(...fields.map(field => Number(body[field])), now).run();
    return json({ ok: true, ...await publicConfig(env) });
  }
if (url.pathname === '/v1/admin/products' && request.method === 'GET') return json({ ok: true, products: await gameStats(env, now), settings: await publicConfig(env) });
  if (url.pathname === '/v1/admin/keys' && request.method === 'POST') {
    const body = await bodyJson(request), product = requireProduct(body.product);
    const label = typeof body.label === 'string' ? body.label.trim() : '';
    if (label.length > 60 || /[\u0000-\u001f]/.test(label)) fail(400, 'LABEL_INVALID', 'Use uma identificação de até 60 caracteres.');
    return issueKey(env, product, label, durationSeconds(body), now);
  }
  if (url.pathname === '/v1/admin/keys' && request.method === 'GET') {
    const product = requireProduct(url.searchParams.get('product') || 'scripts');
    const search = (url.searchParams.get('search') || '').trim(), status = url.searchParams.get('status') || 'all';
    const page = Number(url.searchParams.get('page') || 1);
    if (search.length > 60 || !['all','active','paused','expired','revoked','deleted'].includes(status) || !Number.isInteger(page) || page < 1 || page > 10000) fail(400, 'FILTER_INVALID', 'Filtro inválido.');
    const conditions = ['product = ?', status === 'deleted' ? 'deleted_at IS NOT NULL' : 'deleted_at IS NULL'], args = [product];
    if (search) {
      conditions.push("(label LIKE ? ESCAPE '\\' OR display_key LIKE ? ESCAPE '\\')");
      const query = '%' + search.replace(/[\\%_]/g, '\\$&') + '%'; args.push(query,query);
    }
    if (status === 'active') { conditions.push('revoked_at IS NULL AND paused_at IS NULL AND (expires_at IS NULL OR expires_at > ?)'); args.push(now); }
    if (status === 'paused') { conditions.push('revoked_at IS NULL AND paused_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)'); args.push(now); }
    if (status === 'expired') { conditions.push('revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?'); args.push(now); }
    if (status === 'revoked') conditions.push('revoked_at IS NOT NULL');
    const where = ' WHERE ' + conditions.join(' AND ');
    const [rows,total,stats] = await env.DB.batch([
      env.DB.prepare('SELECT * FROM licenses' + where + ' ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?').bind(...args,PAGE_SIZE,(page-1)*PAGE_SIZE),
      env.DB.prepare('SELECT COUNT(*) AS count FROM licenses' + where).bind(...args),
      env.DB.prepare(`SELECT COALESCE(SUM(deleted_at IS NULL),0) AS total,
        COALESCE(SUM(deleted_at IS NULL AND revoked_at IS NULL AND paused_at IS NULL AND (expires_at IS NULL OR expires_at > ?)),0) AS active,
        COALESCE(SUM(deleted_at IS NULL AND revoked_at IS NULL AND paused_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)),0) AS paused,
        COALESCE(SUM(deleted_at IS NULL AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?),0) AS expired,
        COALESCE(SUM(deleted_at IS NULL AND revoked_at IS NOT NULL),0) AS revoked,
        COALESCE(SUM(deleted_at IS NOT NULL),0) AS deleted FROM licenses WHERE product = ?`).bind(now,now,now,product)
    ]);
    return json({ ok:true, items: rows.results.map(row=>licenseView(row,now)), total:total.results[0].count,
      page,pageSize:PAGE_SIZE,stats:stats.results[0],products:await gameStats(env,now),settings:await publicConfig(env) });
  }
  const action = /^\/v1\/admin\/keys\/([a-f0-9-]{36})\/(copy|delete|restore|pause|resume|revoke)$/.exec(url.pathname);
  if (action && request.method === 'POST') {
    const body = await bodyJson(request), product = requireProduct(body.product);
    const row = await env.DB.prepare('SELECT * FROM licenses WHERE id = ? AND product = ?').bind(action[1],product).first();
    if (!row) fail(404,'KEY_NOT_FOUND','Key não encontrada neste painel.');
    if (action[2] === 'copy') {
      if (row.deleted_at !== null) fail(409,'KEY_UNAVAILABLE','Restaure a key para copiar.');
      return json({ ok:true,key:await decryptKey(env,row) });
    }
    if (action[2] === 'delete') {
      await env.DB.prepare('UPDATE licenses SET deleted_at = COALESCE(deleted_at, ?), updated_at = ? WHERE id = ? AND product = ?').bind(now,now,row.id,product).run();
      return json({ ok:true,status:'deleted' });
    }
    if (action[2] === 'restore') {
      await env.DB.prepare('UPDATE licenses SET deleted_at = NULL, updated_at = ? WHERE id = ? AND product = ?').bind(now,row.id,product).run();
      return json({ ok:true,license:licenseView({...row,deleted_at:null},now) });
    }
    if (row.deleted_at !== null) fail(409,'KEY_UNAVAILABLE','Esta key está em Excluídas.');
    if (action[2] === 'revoke') {
      await env.DB.prepare('UPDATE licenses SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND product = ?').bind(now,row.id,product).run();
      return json({ ok:true,status:'revoked' });
    }
    if (row.revoked_at !== null || row.expires_at !== null && row.expires_at <= now) fail(409,'KEY_UNAVAILABLE','A key expirou ou foi revogada.');
    await env.DB.prepare('UPDATE licenses SET paused_at = ?, updated_at = ? WHERE id = ? AND product = ?')
      .bind(action[2] === 'pause' ? now : null,now,row.id,product).run();
    return json({ ok:true,status:action[2] === 'pause' ? 'paused':'active' });
  }
  fail(404, 'NOT_FOUND', 'Endereço não encontrado.');
}
export default {
  async fetch(request, env) {
    let response;
    try { await ensureSchema(env); response = await route(request, env); }
    catch (error) {
      if (error instanceof ApiError) {
        response = json({ ok: false, error: { code: error.code, message: error.message } }, error.status);
        if (error.retryAfter) response.headers.set('Retry-After', String(error.retryAfter));
      } else {
        console.error('cpioa-keys: falha interna de armazenamento ou configuração');
        response = json({ ok: false, error: { code: 'SERVICE_UNAVAILABLE', message: 'Serviço indisponível. Tente novamente.' } }, 503);
      }
    }
    return secureResponse(response, request.headers.get('Origin'), env);
  },
  async scheduled(controller, env, context) {
    const now = nowSeconds();
    const work = env.DB.batch([
      env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?').bind(now),
      env.DB.prepare('DELETE FROM rate_limits WHERE reset_at <= ?').bind(now)
    ]);
    if (context?.waitUntil) context.waitUntil(work); else await work;
  }
};
