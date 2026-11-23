export async function call(path,body){
 const r=await fetch(path,body===undefined?{}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const data=await r.json().catch(()=>({}));
 if(!r.ok)throw new Error(typeof data.detail==="string"?data.detail:JSON.stringify(data.detail||"Request failed"));
 return data;
}
