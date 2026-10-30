'use client';
import {ReactNode} from 'react';
import {useT} from '@/lib/i18n';
import {useWorkspace} from '@/lib/workspace';

export function PageHead({title, description, crumbs, actions}:
  {title: string; description?: ReactNode; crumbs?: ReactNode; actions?: ReactNode}) {
  return <div className="page-head">
    <div>{crumbs && <div className="crumbs">{crumbs}</div>}<h1>{title}</h1>{description && <p>{description}</p>}</div>
    {actions && <div className="actions">{actions}</div>}
  </div>;
}

export function Badge({tone = '', children}: {tone?: string; children: ReactNode}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Figures({items}: {items: {label: string; value: ReactNode; tone?: string}[]}) {
  return <div className="figures">{items.map(item =>
    <div key={item.label} className={`figure ${item.tone || ''}`}><b>{item.value}</b><span>{item.label}</span></div>)}</div>;
}

export function ErrorNote({message}: {message: string}) {
  return message ? <p className="notice error" role="alert">{message}</p> : null;
}

export function Empty({title, children}: {title: string; children?: ReactNode}) {
  return <div className="empty"><strong>{title}</strong>{children}</div>;
}

/** Renders children only once a workspace is selected; explains what to do otherwise. */
export function RequireWorkspace({children}: {children: (workspaceId: string) => ReactNode}) {
  const {workspaceId, loading, error, workspaces} = useWorkspace();
  const {t} = useT();
  if (loading) return <p className="muted">{t('common.loadingWorkspaces')}</p>;
  if (error) return <ErrorNote message={error}/>;
  if (!workspaces.length) return <div className="panel"><Empty title={t('ws.none')}>{t('ws.noneBody')}</Empty></div>;
  return <>{children(workspaceId)}</>;
}
