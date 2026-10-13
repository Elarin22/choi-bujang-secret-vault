import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createNotesHandler } from '../src/notes-api.mjs';

test('A/B can use their own CRUD; cross-owner operations and owner changes fail', async () => {
  const a=randomUUID(), b=randomUUID(), rows=new Map();
  const clientFactory=()=>({from(){
    const filters=[];let action='read',value;
    const matching=()=>[...rows.values()].filter(r=>filters.every(([k,v])=>r[k]===v));
    const clean=r=>r?{id:r.id,title:r.title,body:r.body}:null;
    const q={select(){return q;},eq(k,v){filters.push([k,v]);return q;},insert(v){action='insert';value=v;return q;},update(v){action='update';value=v;return q;},delete(){action='delete';return q;},
      async order(){return {data:matching().map(clean),error:null};},async single(){return q.maybeSingle();},async maybeSingle(){
        const row=action==='insert'?value:matching()[0];
        if(row&&action==='insert')rows.set(row.id,row);
        if(row&&action==='update')Object.assign(row,value);
        if(row&&action==='delete')rows.delete(row.id);
        return {data:clean(row),error:null};
      }};return q;
  }});
  const options={approvalVerifier:async()=>true,env:{SUPABASE_URL:'https://example.supabase.co',SUPABASE_SECRET_KEY:'unit-test-only'},clientFactory,
    verifierFactory:()=>async auth=>({userId:auth==='Bearer A'?a:b})};
  const list=createNotesHandler(options), item=createNotesHandler({...options,item:true});
  const call=async(identity,method,id,body)=>{
    const res={setHeader(){},status(code){this.code=code;return this;},json(body){this.body=body;return this;}};
    await (id?item:list)({method,query:{id},body,headers:{authorization:`Bearer ${identity}`}},res);return res;
  };
  const owned={};
  for(const identity of ['A','B']) {
    const result=await call(identity,'POST',undefined,{title:'Fixture',body:'Fictional test',owner_id:identity==='A'?b:a});
    assert.equal(result.code,201);owned[identity]=result.body.id;
    assert.equal(rows.get(result.body.id).owner_id,identity==='A'?a:b);
  }
  for(const [actor,other] of [['A','B'],['B','A']]) {
    const own=owned[actor], foreign=owned[other], before=structuredClone(rows.get(foreign));
    const listed=await call(actor,'GET');assert.deepEqual(listed.body.map(r=>r.id),[own]);
    for(const method of ['GET','PUT','DELETE']) {
      const result=await call(actor,method,foreign,{title:'Forbidden',body:'Forbidden'});
      assert.equal(result.code,404);assert.deepEqual(result.body,{error:'note_not_found'});
      assert.deepEqual(rows.get(foreign),before);
    }
    const changed=await call(actor,'PUT',own,{title:'Test',body:'Test',owner_id:actor==='A'?b:a});
    assert.equal(changed.code,400);assert.equal(rows.get(own).owner_id,actor==='A'?a:b);
    assert.equal((await call(actor,'GET',own)).code,200);
    assert.equal((await call(actor,'PUT',own,{title:'Updated',body:'Updated'})).code,200);
  }
  for(const actor of ['A','B']) {
    assert.equal((await call(actor,'DELETE',owned[actor])).code,200);
    assert.equal((await call(actor,'GET',owned[actor])).code,404);
  }
});
