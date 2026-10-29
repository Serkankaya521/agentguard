'use client';
import Link from 'next/link';
import {usePathname} from 'next/navigation';
import {ReactNode} from 'react';
import {useWorkspace, WorkspaceProvider} from '@/lib/workspace';

const NAV: {heading: string; links: [string, string][]}[] = [
  {heading: 'Testing', links: [['/', 'Overview'], ['/campaigns', 'Campaigns'], ['/coverage', 'Coverage'],
                               ['/findings', 'Findings'], ['/evidence', 'Regression cases']]},
  {heading: 'Runtime defense', links: [['/policies', 'Policies'], ['/approvals', 'Approvals'], ['/assets', 'Assets']]},
  {heading: 'Administration', links: [['/workspaces', 'Workspaces'], ['/reports', 'Reports'],
                                      ['/integrations', 'Integrations'], ['/operations', 'Usage and limits']]},
];

function active(pathname: string, href: string): boolean {
  return href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(href + '/');
}

function WorkspaceSwitch() {
  const {workspaces, workspaceId, setWorkspaceId} = useWorkspace();
  if (workspaces.length < 1) return null;
  return <div className="workspace-switch">
    <label htmlFor="workspace">Workspace</label>
    <select id="workspace" value={workspaceId} onChange={event => setWorkspaceId(event.target.value)}>
      {workspaces.map(workspace => <option key={workspace.id} value={workspace.id}>{workspace.name}</option>)}
    </select>
  </div>;
}

async function signOut() {
  await fetch('/api/session', {method: 'DELETE'}).catch(() => undefined);
  location.assign('/login');
}

export function Shell({children}: {children: ReactNode}) {
  const pathname = usePathname() || '/';
  const isLogin = pathname.startsWith('/login');
  // The login page must not call the control API: a 401 there would redirect to itself.
  if (isLogin) return <WorkspaceProvider enabled={false}><main className="content">{children}</main></WorkspaceProvider>;
  return <WorkspaceProvider enabled>
    <div className="shell">
      <aside className="sidebar">
        <Link className="brand" href="/">
          <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 16 16" fill="none">
            <path d="M8 1.5 2.5 3.5v4c0 3.4 2.3 6 5.5 7 3.2-1 5.5-3.6 5.5-7v-4L8 1.5Z" stroke="#fff" strokeWidth="1.6"/>
            <path d="m5.5 8 1.8 1.8L10.8 6" stroke="#fff" strokeWidth="1.6"/></svg></span>
          AgentGuard
        </Link>
        <WorkspaceSwitch/>
        <nav aria-label="Main">{NAV.map(group => <div className="nav-group" key={group.heading}>
          <h4>{group.heading}</h4>
          {group.links.map(([href, label]) =>
            <Link key={href} href={href} aria-current={active(pathname, href) ? 'page' : undefined}>{label}</Link>)}
        </div>)}</nav>
        <div className="sidebar-foot"><button onClick={signOut}>Sign out</button></div>
      </aside>
      <main className="content">{children}</main>
    </div>
  </WorkspaceProvider>;
}
