import type {Metadata} from 'next';
import {ReactNode} from 'react';
import {Shell} from '@/components/shell';
import './globals.css';

export const metadata: Metadata = {title: 'AgentGuard Console', description: 'Adversarial testing and evidence for AI agents'};

export default function Layout({children}: {children: ReactNode}) {
  return <html lang="en"><body><Shell>{children}</Shell></body></html>;
}
