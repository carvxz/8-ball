import { DatabaseSync } from 'node:sqlite';
export class D1 {
  constructor(database) { this.raw=database || new DatabaseSync(':memory:'); }
  prepare(sql) { return new Statement(this,sql); }
  async batch(statements) {
    this.raw.exec('BEGIN');
    try {
      const results=[];
      for(const statement of statements) {
        results.push(/^(?:\s*)(?:SELECT|PRAGMA|WITH)|\bRETURNING\b/i.test(statement.sql)?await statement.all():await statement.run());
      }
      this.raw.exec('COMMIT'); return results;
    } catch(error) { this.raw.exec('ROLLBACK'); throw error; }
  }
}
class Statement {
  constructor(db,sql,args=[]) { this.db=db;this.sql=sql;this.args=args; }
  bind(...args) { return new Statement(this.db,this.sql,args); }
  async first() { return this.db.raw.prepare(this.sql).get(...this.args)||null; }
  async all() { return {success:true,results:this.db.raw.prepare(this.sql).all(...this.args)}; }
  async run() { const info=this.db.raw.prepare(this.sql).run(...this.args);return {success:true,results:[],meta:{changes:Number(info.changes)}}; }
}
export function originalSchema(db) {
  db.raw.exec(`
    CREATE TABLE licenses(id TEXT PRIMARY KEY,key_hash TEXT NOT NULL UNIQUE,display_key TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,expires_at INTEGER,paused_at INTEGER,revoked_at INTEGER,updated_at INTEGER);
    CREATE TABLE admin_sessions(token_hash TEXT PRIMARY KEY,password_version TEXT NOT NULL,expires_at INTEGER NOT NULL);
    CREATE TABLE rate_limits(bucket TEXT PRIMARY KEY,window_start INTEGER NOT NULL,reset_at INTEGER NOT NULL,hits INTEGER NOT NULL);
    CREATE TABLE system_settings(id INTEGER PRIMARY KEY,access_paused INTEGER NOT NULL,generation_paused INTEGER NOT NULL,updated_at INTEGER NOT NULL);
    INSERT INTO system_settings VALUES(1,0,1,0);
  `);
}
