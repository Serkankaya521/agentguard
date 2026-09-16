import type {Metadata} from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata:Metadata={title:'AgentGuard Console',description:'Tenant-safe enterprise security control plane'};
const links=[['/campaigns','Campaigns'],['/findings','Findings'],['/approvals','Approvals'],['/assets','Assets'],['/policies','Policies'],['/evidence','Evidence'],['/operations','Operations'],['/workspaces','Workspaces']];
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body><header><Link className="brand" href="/">AGENT<b>GUARD</b></Link><nav>{links.map(([href,label])=><Link key={href} href={href}>{label}</Link>)}</nav></header><main>{children}</main></body></html>}
