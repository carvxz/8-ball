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
    maxUsers: row.max_users ?? null, userCount: Number(row.user_count || 0),
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
      if (!columns.has('max_users')) changes.push(env.DB.prepare('ALTER TABLE licenses ADD COLUMN max_users INTEGER CHECK (max_users IS NULL OR max_users BETWEEN 1 AND 1000)'));
      if (migrateLegacy) changes.push(env.DB.prepare('UPDATE licenses SET deleted_at = ?, updated_at = ? WHERE deleted_at IS NULL').bind(nowSeconds(), nowSeconds()));
      if (changes.length) {
        try { await env.DB.batch(changes); }
        catch (error) {
          // Another isolate may have completed the same atomic migration first.
          if (!/duplicate column name/i.test(String(error?.message))) throw error;
          const complete = new Set((await env.DB.prepare('PRAGMA table_info(licenses)').all()).results.map(row => row.name));
          if (!['product','key_ciphertext','deleted_at','max_users'].every(name => complete.has(name))) throw error;
        }
      }
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS licenses_product_created ON licenses(product, deleted_at, created_at DESC)').run();
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS license_users (
        id TEXT PRIMARY KEY, license_id TEXT NOT NULL REFERENCES licenses(id), device_hash TEXT NOT NULL,
        user_name TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, revoked_at INTEGER,
        UNIQUE(license_id,device_hash))`).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS license_users_active ON license_users(license_id,revoked_at,created_at)').run();
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
    keyHours: hours, checkAfterSeconds, turnstileSiteKey: siteKey, userLimits: true, maxUserLimit: 1000 };
}
function userLimit(value) {
  if (value === null) return null;
  if (!Number.isInteger(value) || value < 1 || value > 1000) fail(400,'USER_LIMIT_INVALID','Informe um limite inteiro de 1 a 1000 usuários.');
  return value;
}
function userIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400,'KEY_REGISTRATION_REQUIRED','Informe seu nome no aplicativo atualizado para vincular este aparelho.');
  const name = typeof value.name === 'string' ? value.name.normalize('NFKC').trim() : '';
  if (!/^[\p{L}\p{N}][\p{L}\p{M}\p{N} ._-]{1,39}$/u.test(name)) fail(400,'USER_NAME_INVALID','Use um nome de 2 a 40 caracteres, com letras, números, espaço, ponto, traço ou sublinhado.');
  if (typeof value.deviceId !== 'string' || !/^[a-f0-9]{64}$/.test(value.deviceId)) fail(400,'DEVICE_INVALID','Não foi possível identificar este aparelho. Abra o aplicativo novamente.');
  return {name,deviceId:value.deviceId};
}
function registeredUser(row) {
  return {id:row.id,name:row.user_name,device:row.id.slice(0,8),createdAt:row.created_at,lastSeenAt:row.last_seen_at,
    removedAt:row.revoked_at,status:row.revoked_at === null ? 'active' : 'removed'};
}
async function registerUser(request,env,row,input,now) {
  if (input === undefined && row.max_users === null) return null; // Existing unlimited clients remain compatible.
  const user = userIdentity(input);
  await rateLimit(request,env,'verify-user',120,60,now);
  const deviceHash = await sha256(row.id + ':' + user.deviceId);
  // The capacity check and insertion are ONE SQLite statement. Parallel first
  // logins cannot both claim the final seat; an existing device can re-enter.
  const binding = await env.DB.prepare(`INSERT INTO license_users(id,license_id,device_hash,user_name,created_at,last_seen_at)
    SELECT ?,l.id,?,?,?,? FROM licenses l WHERE l.id = ? AND l.deleted_at IS NULL AND l.revoked_at IS NULL
      AND l.paused_at IS NULL AND (l.expires_at IS NULL OR l.expires_at > ?)
      AND (EXISTS(SELECT 1 FROM license_users u WHERE u.license_id=l.id AND u.device_hash=? AND u.revoked_at IS NULL)
        OR (NOT EXISTS(SELECT 1 FROM license_users u WHERE u.license_id=l.id AND u.device_hash=?)
          AND (l.max_users IS NULL OR (SELECT COUNT(*) FROM license_users u WHERE u.license_id=l.id AND u.revoked_at IS NULL)<l.max_users)))
    ON CONFLICT(license_id,device_hash) DO UPDATE SET user_name=excluded.user_name,last_seen_at=excluded.last_seen_at
      WHERE license_users.revoked_at IS NULL
    RETURNING id,user_name,created_at,last_seen_at,revoked_at`)
    .bind(crypto.randomUUID(),deviceHash,user.name,now,now,row.id,now,deviceHash,deviceHash).first();
  if (!binding) {
    const previous=await env.DB.prepare('SELECT revoked_at FROM license_users WHERE license_id=? AND device_hash=?').bind(row.id,deviceHash).first();
    if (previous?.revoked_at !== null && previous) fail(403,'KEY_USER_REMOVED','Este aparelho foi removido desta key pelo administrador.');
    const current=await env.DB.prepare('SELECT max_users,deleted_at,revoked_at,paused_at,expires_at FROM licenses WHERE id=?').bind(row.id).first();
    if (!current || current.deleted_at!==null || current.revoked_at!==null || current.paused_at!==null || current.expires_at!==null && current.expires_at<=now) fail(403,'KEY_UNAVAILABLE','Esta key não está disponível.');
    fail(403,'KEY_USER_LIMIT','O limite de usuários desta key foi atingido.');
  }
  const count=await env.DB.prepare('SELECT COUNT(*) AS count FROM license_users WHERE license_id=? AND revoked_at IS NULL').bind(row.id).first();
  return {...registeredUser(binding),used:count.count,max:row.max_users};
}
async function issueKey(env, product, label, seconds, now, maxUsers) {
  const key = newKey(product), id = crypto.randomUUID(), expiresAt = seconds === null ? null : now + seconds;
  const displayKey = key.slice(0, PRODUCTS[product].prefix.length + 6) + '…' + key.slice(-6);
  const encrypted = await encryptKey(env, key, id, product);
  await env.DB.prepare(`INSERT INTO licenses(id, key_hash, display_key, label, created_at, expires_at, product, key_ciphertext, max_users)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, await sha256(key), displayKey, label, now, expiresAt, product, encrypted, maxUsers).run();
  return json({ ok: true, key, license: { id, product, displayKey, label, createdAt: now, expiresAt, status: 'active', canCopy: true, maxUsers, userCount: 0 } }, 201);
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
    return json({ ok: true, service: 'cpioa-keys', accessPaused: config.accessPaused, publicGeneration: config.publicGeneration, userLimits: true });
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
    const row = await env.DB.prepare('SELECT id, expires_at, revoked_at, paused_at, deleted_at, product, max_users FROM licenses WHERE key_hash = ?').bind(await sha256(key)).first();
    if (!row) { await rateLimit(request, env, 'verify-invalid', 30, 60, now); fail(401, 'KEY_INVALID', 'Key inválida.'); }
    if (row.product !== product) fail(401, 'KEY_WRONG_APP', 'Esta key pertence a outro painel.');
    if (row.deleted_at !== null) fail(401, 'KEY_DELETED', 'Esta key foi excluída.');
    if (row.revoked_at !== null) fail(401, 'KEY_REVOKED', 'Esta key foi revogada.');
    if (row.expires_at !== null && row.expires_at <= now) fail(401, 'KEY_EXPIRED', 'Esta key expirou.');
    if (row.paused_at !== null) fail(403, 'KEY_PAUSED', 'Esta key está pausada.');
    const registration=await registerUser(request,env,row,body.user,now);
    return json({ ok: true, registration, license: { id: row.id, product, expiresAt: row.expires_at, status: 'active', maxUsers: row.max_users }, serverTime: now,
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
    return issueKey(env, product, label, durationSeconds(body), now, userLimit(Object.hasOwn(body,'maxUsers') ? body.maxUsers : null));
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
      env.DB.prepare('SELECT *, (SELECT COUNT(*) FROM license_users u WHERE u.license_id=licenses.id AND u.revoked_at IS NULL) AS user_count FROM licenses' + where + ' ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?').bind(...args,PAGE_SIZE,(page-1)*PAGE_SIZE),
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
  const usersRoute=/^\/v1\/admin\/keys\/([a-f0-9-]{36})\/users$/.exec(url.pathname);
  if (usersRoute && request.method==='GET') {
    const product=requireProduct(url.searchParams.get('product'));
    const row=await env.DB.prepare('SELECT * FROM licenses WHERE id=? AND product=?').bind(usersRoute[1],product).first();
    if (!row) fail(404,'KEY_NOT_FOUND','Key não encontrada neste painel.');
    const users=(await env.DB.prepare('SELECT id,user_name,created_at,last_seen_at,revoked_at FROM license_users WHERE license_id=? ORDER BY revoked_at IS NOT NULL,created_at,id').bind(row.id).all()).results;
    return json({ok:true,license:licenseView({...row,user_count:users.filter(user=>user.revoked_at===null).length},now),users:users.map(registeredUser)});
  }
  const limitRoute=/^\/v1\/admin\/keys\/([a-f0-9-]{36})\/user-limit$/.exec(url.pathname);
  if (limitRoute && request.method==='POST') {
    const body=await bodyJson(request),product=requireProduct(body.product),limit=userLimit(body.maxUsers);
    const changed=await env.DB.prepare(`UPDATE licenses SET max_users=?,updated_at=? WHERE id=? AND product=? AND deleted_at IS NULL
      AND (? IS NULL OR (SELECT COUNT(*) FROM license_users u WHERE u.license_id=licenses.id AND u.revoked_at IS NULL)<=?) RETURNING id`)
      .bind(limit,now,limitRoute[1],product,limit,limit).first();
    if (!changed) {
      const row=await env.DB.prepare('SELECT deleted_at FROM licenses WHERE id=? AND product=?').bind(limitRoute[1],product).first();
      if (!row) fail(404,'KEY_NOT_FOUND','Key não encontrada neste painel.');
      if (row.deleted_at!==null) fail(409,'KEY_UNAVAILABLE','Restaure a key antes de alterar o limite.');
      fail(409,'USER_LIMIT_BELOW_USAGE','Remova usuários antes de reduzir o limite abaixo das vagas ocupadas.');
    }
    return json({ok:true,maxUsers:limit});
  }
  const userAction=/^\/v1\/admin\/keys\/([a-f0-9-]{36})\/users\/([a-f0-9-]{36})\/(remove|restore)$/.exec(url.pathname);
  if (userAction && request.method==='POST') {
    const body=await bodyJson(request),product=requireProduct(body.product);
    const license=await env.DB.prepare('SELECT * FROM licenses WHERE id=? AND product=?').bind(userAction[1],product).first();
    if (!license) fail(404,'KEY_NOT_FOUND','Key não encontrada neste painel.');
    if (license.deleted_at!==null) fail(409,'KEY_UNAVAILABLE','Restaure a key antes de alterar seus usuários.');
    const user=await env.DB.prepare('SELECT * FROM license_users WHERE id=? AND license_id=?').bind(userAction[2],license.id).first();
    if (!user) fail(404,'USER_NOT_FOUND','Usuário não encontrado nesta key.');
    if (userAction[3]==='remove') {
      await env.DB.prepare('UPDATE license_users SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND license_id=?').bind(now,user.id,license.id).run();
    } else if (user.revoked_at!==null) {
      const restored=await env.DB.prepare(`UPDATE license_users SET revoked_at=NULL WHERE id=? AND license_id=?
        AND EXISTS(SELECT 1 FROM licenses l WHERE l.id=license_users.license_id AND (l.max_users IS NULL OR
          (SELECT COUNT(*) FROM license_users u WHERE u.license_id=l.id AND u.revoked_at IS NULL)<l.max_users)) RETURNING id`)
        .bind(user.id,license.id).first();
      if (!restored) fail(409,'KEY_USER_LIMIT','A key não tem vaga livre para reativar este usuário.');
    }
    return json({ok:true,status:userAction[3]==='remove'?'removed':'active'});
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
