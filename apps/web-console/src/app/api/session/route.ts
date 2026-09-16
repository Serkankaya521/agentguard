import {NextRequest,NextResponse} from 'next/server';

export async function POST(request:NextRequest){
  const origin=process.env.WEB_CONSOLE_ORIGIN;
  if(process.env.NODE_ENV==='production'&&!origin)return NextResponse.json({code:'ORIGIN_POLICY_MISSING'},{status:503});
  if(origin&&request.headers.get('origin')!==origin)return NextResponse.json({code:'ORIGIN_DENIED'},{status:403});
  if(Number(request.headers.get('content-length')||0)>1024)return NextResponse.json({code:'PAYLOAD_TOO_LARGE'},{status:413});
  const body=await request.json().catch(()=>({}));
  if(typeof body.token!=='string'||body.token.length<32||body.token.length>256)
    return NextResponse.json({code:'INVALID_TOKEN'},{status:422});
  const response=NextResponse.json({authenticated:true},{headers:{'Cache-Control':'no-store'}});
  response.cookies.set('agentguard_session',body.token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/',maxAge:3600});
  return response;
}
export async function DELETE(){const response=NextResponse.json({authenticated:false});response.cookies.delete('agentguard_session');return response}
