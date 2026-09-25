import type {Metadata} from 'next';
import {AppShell} from '@/components/app-shell';
import './globals.css';

export const metadata:Metadata={title:'AgentGuard | AI Security Operations',description:'Continuous adversarial validation for autonomous agents'};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body><AppShell>{children}</AppShell></body></html>}
