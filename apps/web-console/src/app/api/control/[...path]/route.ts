import {NextRequest,NextResponse} from 'next/server';

async function proxy(request:NextRequest,{params}:{params:Promise<{path:string[]}>}){
  const token=request.cookies.get('agentguard_session')?.value;
  if(!token)return NextResponse.json({code:'UNAUTHENTICATED'},{status:401});
  const segments=(await params).path;
  if(!segments.length||segments[0]!=='v1'||segments.some(p=>!/^[-A-Za-z0-9._]+$/.test(p)))
    return NextResponse.json({code:'PATH_DENIED'},{status:400});
  if(!['GET','POST','PUT','DELETE'].includes(request.method))return NextResponse.json({code:'METHOD_DENIED'},{status:405});
  if(request.method!=='GET'){
    const origin=process.env.WEB_CONSOLE_ORIGIN;
    if(process.env.NODE_ENV==='production'&&!origin)return NextResponse.json({code:'ORIGIN_POLICY_MISSING'},{status:503});
    if(origin&&request.headers.get('origin')!==origin)return NextResponse.json({code:'ORIGIN_DENIED'},{status:403});
    if(Number(request.headers.get('content-length')||0)>8192)return NextResponse.json({code:'PAYLOAD_TOO_LARGE'},{status:413});
  }
  const base=process.env.CONTROL_API_URL;
  if(!base)return NextResponse.json({code:'CONTROL_API_UNAVAILABLE'},{status:503});
  const target=new URL('/'+segments.join('/'),base);target.search=request.nextUrl.search;
  const headers:Record<string,string>={'Authorization':'Bearer '+token,'Accept':'application/json'};
  for(const name of ['content-type','if-match','idempotency-key']){const value=request.headers.get(name);if(value)headers[name]=value}
  const upstream=await fetch(target,{method:request.method,headers,body:request.method==='GET'?undefined:await request.arrayBuffer(),cache:'no-store',signal:AbortSignal.timeout(5000)});
  return new NextResponse(upstream.body,{status:upstream.status,headers:{'Content-Type':upstream.headers.get('content-type')||'application/json','Cache-Control':'no-store','X-Correlation-ID':upstream.headers.get('x-correlation-id')||''}});
}
export const GET=proxy;export const POST=proxy;export const PUT=proxy;export const DELETE=proxy;
