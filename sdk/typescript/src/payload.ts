/** Strict byte-level validation of signed payloads. */
type Kind = 's'|'b'|'i'|'m'|'M';
type Schema = Record<string, [Kind, boolean]>;
export const MEMBER: Schema = {device:['s',true],name:['s',true],public_key:['s',true],signing_key:['s',true],manager:['b',true]};
export const STATE: Schema = {closed:['b',false],name:['s',false],version:['i',true],app:['s',true],group:['s',true],revision:['i',true],previous:['s',true],members:['M',true],invitation:['s',true],request_hash:['s',true]};
export const REQUEST: Schema = {version:['i',true],app:['s',true],group:['s',true],invitation:['s',true],member:['m',true],token_hash:['s',true]};
export const GRANT: Schema = {version:['i',true],purpose:['s',true],mode:['s',true],app:['s',true],group:['s',true],invitation:['s',true],expires:['i',true],secret_hash:['s',true],delegate_key:['s',true],anchor_revision:['i',true],anchor_hash:['s',true]};
export const SCHEMAS = [STATE, REQUEST, GRANT];
export function strict(raw: Uint8Array, schema: Schema): boolean {
  try { new TextDecoder('utf-8',{fatal:true}).decode(raw); } catch { return false; }
  const b=Buffer.from(raw); let i=0;
  const ws=()=>{while(i<b.length && [32,9,10,13].includes(b[i]!)) i++;};
  const eat=(c:number)=>{ws(); if(b[i]===c){i++;return true;}return false;};
  function str():boolean { if(b[i++]!==34)return false; while(i<b.length){const c=b[i++]!;if(c===34)return true;if(c<32)return false;if(c===92){const e=b[i++];if(e===117){const h=b.subarray(i,i+4).toString('latin1');if(!/^[0-9a-fA-F]{4}$/.test(h)|| (parseInt(h,16)>=0xd800&&parseInt(h,16)<=0xdfff))return false;i+=4;}else if(e===undefined||![34,92,47,98,102,110,114,116].includes(e))return false;}}return false;}
  function value(k:Kind):boolean {ws();if(k==='s')return str();if(k==='b'){for(const w of ['true','false'])if(b.subarray(i,i+w.length).toString()===w){i+=w.length;return true;}return false;}if(k==='i'){const start=i;while(i<b.length&&b[i]!>=48&&b[i]!<=57)i++;const s=b.subarray(start,i).toString();return /^(0|[1-9][0-9]*)$/.test(s)&&BigInt(s)<=9007199254740991n;}if(k==='m')return obj(MEMBER);if(!eat(91))return false;if(eat(93))return true;do{if(!obj(MEMBER))return false;if(eat(93))return true;}while(eat(44));return false;}
  function obj(s:Schema):boolean {if(!eat(123))return false;const seen=new Set<string>();if(!eat(125)){do{ws();const start=i;if(!str())return false;const key=b.subarray(start+1,i-1).toString();const f=Object.hasOwn(s,key)?s[key]:undefined;if(!f||seen.has(key)||!eat(58)||!value(f[0]))return false;seen.add(key);if(eat(125))return Object.entries(s).every(([k,v])=>!v[1]||seen.has(k));}while(eat(44));return false;}return Object.entries(s).every(([k,v])=>!v[1]||seen.has(k));}
  const ok=obj(schema);ws();return ok&&i===b.length;
}
