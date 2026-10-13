import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { createNotesHandler } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
const response = () => ({ headers: {}, setHeader(k,v) { this.headers[k]=v; }, status(code) { this.code=code; return this; }, json(body) { this.body=body; return this; } });
const env = { SUPABASE_URL: config.identityProvider.issuer.replace('/auth/v1',''), SUPABASE_SECRET_KEY: 'unit-test-only' };
test('server rejects absent and failed authentication before accessing storage', async () => {
  const handler = createNotesHandler({ env, verifierFactory: () => async () => null,
    clientFactory: () => { throw new Error('must not connect'); } });
  for (const method of ['GET','POST','PUT','DELETE']) {
    for (const authorization of [undefined,'Bearer invalid']) {
      const res=response(); await handler({method,headers:{authorization}},res);
      assert.equal(res.code,401); assert.ok(!('notes' in res.body));
    }
  }
});
test('provided verifier validates signature, expiry, audience, issuer and subject', async () => {
  const {privateKey,publicKey}=await generateKeyPair('ES256');
  const wrong=await generateKeyPair('ES256');
  const now=Math.floor(Date.now()/1000);
  const claims={iss:config.judgeIssuer,aud:new URL(config.publicAppUrl).hostname,sub:randomUUID(),aleph_run:randomUUID(),aleph_role:'judge',aleph_identity:'a',iat:now,exp:now+600};
  const verify=createLoginVerifier({config,judgeKeySet:async () => publicKey,supabaseClient:{auth:{getClaims:async () => ({error:true})}}});
  const signed = (payload,key=privateKey) => new SignJWT(payload).setProtectedHeader({alg:'ES256'}).sign(key);
  assert.equal((await verify(`Bearer ${await signed(claims)}`)).userId,claims.sub);
  for (const [change,key] of [[{},wrong.privateKey],[{exp:now-100,iat:now-200},privateKey],[{aud:'another.vercel.app'},privateKey],[{iss:'https://other.supabase.co/auth/v1'},privateKey],[{sub:'invalid'},privateKey]]) {
    assert.equal(await verify(`Bearer ${await signed({...claims,...change},key)}`),null);
  }
});
test('CRUD uses verified owner and supports create, read, update, delete, then 404', async () => {
  const userId=randomUUID(), rows=new Map();
  function clientFactory() {
    return { from(table) {
      assert.equal(table,'user_notes');
      let action='read', value; const filters=[];
      const q={select(){return q;},insert(v){action='insert';value=v;return q;},update(v){action='update';value=v;return q;},delete(){action='delete';return q;},eq(k,v){filters.push([k,v]);return q;},
        async order(){return {data:[...rows.values()].filter(r=>filters.every(([k,v])=>r[k]===v)).map(({id,title,body})=>({id,title,body})),error:null};},
        async single(){return q.maybeSingle();},async maybeSingle(){
          let row=action==='insert'?value:[...rows.values()].find(r=>filters.every(([k,v])=>r[k]===v));
          if(action==='insert')rows.set(row.id,row);
          if(row&&action==='update')Object.assign(row,value);
          if(row&&action==='delete')rows.delete(row.id);
          return {data:row?{id:row.id,title:row.title,body:row.body}:null,error:null};
        }};return q;
    }};
  }
  const opts={env,clientFactory,approvalVerifier:async()=>true,verifierFactory:()=>async()=>({kind:'student',userId})};
  const collection=createNotesHandler(opts), item=createNotesHandler({...opts,item:true});
  const call=async(handler,method,body,id)=>{const res=response();await handler({method,body,query:{id},headers:{authorization:'Bearer unit-test'}},res);return res;};
  const added=await call(collection,'POST',{title:'Test',body:'Fictional fixture',owner_id:randomUUID()});
  assert.equal(added.code,201);assert.equal(rows.get(added.body.id).owner_id,userId);
  assert.equal((await call(collection,'GET')).body.length,1);
  assert.equal((await call(item,'GET',undefined,added.body.id)).body.title,'Test');
  assert.equal((await call(item,'PUT',{title:'Updated',body:'Fixture'},added.body.id)).body.title,'Updated');
  assert.equal((await call(item,'DELETE',undefined,added.body.id)).code,200);
  assert.equal((await call(item,'GET',undefined,added.body.id)).code,404);
});
