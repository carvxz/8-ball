import assert from 'node:assert/strict';
import {pbkdf2Sync,createHash,randomUUID} from 'node:crypto';
import worker from './worker.mjs';
import {D1,originalSchema} from './test-db.mjs';

let checks=0;
function check(test,message) { assert.ok(test,message);checks++;console.log('PASS '+message); }
export function testEnvironment() {
  const salt=Buffer.from('local-test-salt!'),password='local-review-only-2026';
  const env={DB:new D1(),ADMIN_PASSWORD_HASH:'pbkdf2-sha256$100000$'+salt.toString('base64')+'$'+pbkdf2Sync(password,salt,100000,32,'sha256').toString('base64'),PUBLIC_GENERATION:'false',ALLOWED_ORIGINS:'https://carvxz.github.io',CHECK_AFTER_SECONDS:'60'};
  originalSchema(env.DB); return {env,password};
}
const {env,password}=testEnvironment();
let adminToken='';
async function api(path,{body,method=body===undefined?'GET':'POST',authorized=false,origin,customToken}={}) {
  const headers={};if(body!==undefined)headers['Content-Type']='application/json';
  if(authorized)headers.Authorization='Bearer '+(customToken||adminToken);
  if(origin)headers.Origin=origin;
  const response=await worker.fetch(new Request('https://keys.example'+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)}),env);
  return {status:response.status,data:response.status===204?null:await response.json(),headers:response.headers};
}
async function verify(key,product) { return api('/v1/verify',{body:{key,...(product===undefined?{}:{product})}}); }
const legacyKey='CPIOA-00000000-00000000-00000000-00000000';
const legacyId=randomUUID(),legacyHash=createHash('sha256').update(legacyKey).digest('hex');
env.DB.raw.prepare('INSERT INTO licenses(id,key_hash,display_key,label,created_at) VALUES(?,?,?,?,?)').run(legacyId,legacyHash,'CPIOA-00000…000000','Legacy',1);
const health=await api('/v1/health');
check(health.status===200,'Old SQLite schema migrates successfully through Worker fetch');
const migrated=env.DB.raw.prepare('SELECT * FROM licenses WHERE id=?').get(legacyId);
check(migrated.product==='scripts' && migrated.deleted_at!==null && migrated.key_hash===legacyHash,'Legacy key is recoverably archived without losing its hash');
check((await verify(legacyKey)).data.error.code==='APP_REQUIRED','Missing app identity never grants access');
check((await verify(legacyKey,'scripts')).data.error.code==='KEY_DELETED','Archived old key is disabled');
check((await api('/v1/admin/keys',{body:{product:'scripts',duration:null}})).status===401,'Generation requires administrator authentication');
check((await api('/v1/admin/login',{body:{password:'incorrect-password'}})).status===401,'Incorrect admin password is rejected');
const login=await api('/v1/admin/login',{body:{password}});adminToken=login.data.token;
check(login.status===200 && /^[a-f0-9]{64}$/.test(adminToken),'Existing PBKDF2 login and hashed server sessions continue to work');
const issued={};
for(const [product,prefix,duration] of [['scripts','CPIOA',null],['8ball','CPIOA8',{value:5,unit:'minutes'}],['freefire','CPIOAff',{value:2,unit:'hours'}]]) {
  const result=await api('/v1/admin/keys',{authorized:true,body:{product,label:'Test '+product,duration}});
  check(result.status===201 && result.data.key.startsWith(prefix+'-'),'Correct generated prefix for '+product);
  issued[product]=result.data;
  const row=env.DB.raw.prepare('SELECT * FROM licenses WHERE id=?').get(result.data.license.id);
  check(row.product===product && row.key_ciphertext && !row.key_ciphertext.includes(result.data.key),'Encrypted copy is stored in the correct product for '+product);
  const seconds=duration===null?null:duration.value*(duration.unit==='minutes'?60:3600);
  check(seconds===null?row.expires_at===null:row.expires_at-row.created_at===seconds,'Exact selected lifetime for '+product);
  const copied=await api(`/v1/admin/keys/${row.id}/copy`,{authorized:true,body:{product}});
  check(copied.status===200 && copied.data.key===result.data.key,'Authorized copy decrypts complete key for '+product);
}
for(const [product,result] of Object.entries(issued)) for(const target of Object.keys(issued)) {
  const response=await verify(result.key,target);
  check(product===target?response.status===200 && response.data.license.product===product:response.status===401 && response.data.error.code==='KEY_WRONG_APP',`Cross-app check ${product} → ${target}`);
}
check((await verify(issued.freefire.key.toLowerCase(),'freefire')).status===200,'Free Fire key normalization preserves canonical CPIOAff prefix');
check((await verify(issued['8ball'].key.replaceAll('-',' \u00a0'),'8ball')).status===200,'Pasted separators and nonbreaking spaces normalize correctly');
for(const product of Object.keys(issued))check((await verify(issued[product].key)).data.error.code==='APP_REQUIRED','New '+product+' key requires explicit app identity');
const forged=issued['8ball'].key.replace('CPIOA8','CPIOAff');
check((await verify(forged,'freefire')).data.error.code==='KEY_INVALID','Changing the visible prefix cannot transplant a license');
const scriptsId=issued.scripts.license.id;
env.DB.raw.prepare('UPDATE licenses SET product=? WHERE id=?').run('8ball',scriptsId);
check((await verify(issued.scripts.key,'scripts')).data.error.code==='KEY_WRONG_APP','Stored product is checked in addition to the prefix');
env.DB.raw.prepare('UPDATE licenses SET product=? WHERE id=?').run('scripts',scriptsId);
check((await api(`/v1/admin/keys/${scriptsId}/copy`,{authorized:true,body:{product:'8ball'}})).status===404,'Admin actions cannot address a key through another game panel');
const list=await api('/v1/admin/keys?product=8ball',{authorized:true});
check(list.data.items.length===1 && list.data.items.every(item=>item.product==='8ball'),'Lists and counts are scoped to the selected game');
check(!JSON.stringify(list.data).includes('key_ciphertext') && !JSON.stringify(list.data).includes('key_hash') && !JSON.stringify(list.data).includes(issued['8ball'].key),'List endpoint never includes full keys, hashes or ciphertext');
check(list.data.products.length===3 && list.data.products.every(game=>game.total===1),'Dashboard summaries show independent per-game totals');
for(const duration of [{value:0,unit:'minutes'},{value:-1,unit:'hours'},{value:1.5,unit:'hours'},{value:'5',unit:'minutes'},{value:525601,unit:'minutes'},{value:8761,unit:'hours'},{value:5,unit:'seconds'},{}]) {
  check((await api('/v1/admin/keys',{authorized:true,body:{product:'scripts',duration}})).data.error.code==='DURATION_INVALID','Reject invalid duration '+JSON.stringify(duration));
}
check((await api('/v1/admin/keys',{authorized:true,body:{product:'__proto__',duration:null}})).data.error.code==='PRODUCT_REQUIRED','Prototype names cannot be used as products');
check((await api('/v1/admin/keys',{authorized:true,body:{product:'scripts',label:'x'.repeat(61),duration:null}})).data.error.code==='LABEL_INVALID','Identification length is enforced on the server');
const id=issued['8ball'].license.id;
await api(`/v1/admin/keys/${id}/pause`,{authorized:true,body:{product:'8ball'}});
check((await verify(issued['8ball'].key,'8ball')).data.error.code==='KEY_PAUSED','Individual pause blocks the correct game key');
await api(`/v1/admin/keys/${id}/resume`,{authorized:true,body:{product:'8ball'}});
check((await verify(issued['8ball'].key,'8ball')).status===200,'Individual resume restores the same license');
await api(`/v1/admin/keys/${id}/delete`,{authorized:true,body:{product:'8ball'}});
check((await verify(issued['8ball'].key,'8ball')).data.error.code==='KEY_DELETED','Deleted key is unusable immediately');
check((await api('/v1/admin/keys?product=8ball',{authorized:true})).data.items.length===0,'Deleted key disappears from normal list');
check((await api('/v1/admin/keys?product=8ball&status=deleted',{authorized:true})).data.items[0].status==='deleted','Deleted keys have a normal recoverable view');
await api(`/v1/admin/keys/${id}/restore`,{authorized:true,body:{product:'8ball'}});
check((await verify(issued['8ball'].key,'8ball')).status===200,'Restore recovers key without changing its original expiry');
const ffId=issued.freefire.license.id;
await api(`/v1/admin/keys/${ffId}/revoke`,{authorized:true,body:{product:'freefire'}});
await api(`/v1/admin/keys/${ffId}/delete`,{authorized:true,body:{product:'freefire'}});
await api(`/v1/admin/keys/${ffId}/restore`,{authorized:true,body:{product:'freefire'}});
check((await verify(issued.freefire.key,'freefire')).data.error.code==='KEY_REVOKED','Restoring a deleted revoked key never reverses revocation');
env.DB.raw.prepare('UPDATE licenses SET expires_at=? WHERE id=?').run(Math.floor(Date.now()/1000)-1,id);
check((await verify(issued['8ball'].key,'8ball')).data.error.code==='KEY_EXPIRED','Minute-based expiry is enforced on server time');
check((await api(`/v1/admin/keys/${id}/resume`,{authorized:true,body:{product:'8ball'}})).status===409,'Expired key cannot be resumed');
await api(`/v1/admin/keys/${legacyId}/restore`,{authorized:true,body:{product:'scripts'}});
check((await api(`/v1/admin/keys/${legacyId}/copy`,{authorized:true,body:{product:'scripts'}})).data.error.code==='KEY_COPY_UNAVAILABLE','Old hash-only key fails copying clearly without inventing its value');
const cipher=env.DB.raw.prepare('SELECT key_ciphertext FROM licenses WHERE id=?').get(scriptsId).key_ciphertext;
const parts=cipher.split('.');const bad=Buffer.from(parts[2],'base64');bad[0]^=1;
env.DB.raw.prepare('UPDATE licenses SET key_ciphertext=? WHERE id=?').run(parts[0]+'.'+parts[1]+'.'+bad.toString('base64'),scriptsId);
check((await api(`/v1/admin/keys/${scriptsId}/copy`,{authorized:true,body:{product:'scripts'}})).status===409,'Authenticated encryption rejects modified stored ciphertext');
env.DB.raw.prepare('UPDATE licenses SET key_ciphertext=? WHERE id=?').run(cipher,scriptsId);
check((await api('/v1/keys',{body:{}})).status===403,'Public generation remains closed');
env.PUBLIC_GENERATION='true';
check((await api('/v1/keys',{body:{}})).status===403,'Public generation cannot reopen through a stale configuration flag');
const cors=await api('/v1/config',{origin:'https://carvxz.github.io'});
check(cors.headers.get('Access-Control-Allow-Origin')==='https://carvxz.github.io','Existing authorized site keeps CORS access');
check((await api('/v1/config',{origin:'https://unrelated.example'})).status===403,'Unlisted browser origin remains blocked');
const binding=env.DB;env.DB=new D1(binding.raw);
check((await verify(issued.scripts.key,'scripts')).status===200,'Cold isolate checks do not archive newly generated keys again');
check((await api('/v1/admin/settings',{authorized:true,body:{accessPaused:true}})).status===200,'Existing global pause remains available');
check((await verify(issued.scripts.key,'scripts')).data.error.code==='ACCESS_PAUSED','Global pause blocks every product');
await api('/v1/admin/settings',{authorized:true,body:{accessPaused:false}});
await api('/v1/admin/logout',{authorized:true,method:'POST'});
check((await api('/v1/admin/products',{authorized:true})).status===401,'Logout invalidates server session');
console.log(JSON.stringify({passed:true,checks,engine:'Actual Worker fetch with real in-memory SQLite and WebCrypto; no production data'}));
