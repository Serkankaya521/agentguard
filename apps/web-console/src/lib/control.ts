'use client';

export async function control<T>(path:string, init:RequestInit={}):Promise<T>{
  const response=await fetch('/api/control/'+path.replace(/^\//,''),{
    ...init,headers:{'Content-Type':'application/json',...(init.headers||{})},cache:'no-store'});
  if(response.status===401){location.assign('/login');throw new Error('UNAUTHENTICATED')}
  const body=await response.json().catch(()=>({code:'INVALID_RESPONSE'}));
  if(!response.ok)throw new Error(body.code||`HTTP_${response.status}`);
  return body as T;
}

export type Row=Record<string,unknown>;
