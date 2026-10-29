'use client';
import {createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState} from 'react';
import {control, Environment, explain, Workspace} from '@/lib/control';

type WorkspaceState = {
  workspaces: Workspace[];
  environments: Environment[];
  workspaceId: string;
  setWorkspaceId: (id: string) => void;
  loading: boolean;
  error: string;
  reload: () => void;
};

const Context = createContext<WorkspaceState | null>(null);
const STORAGE_KEY = 'agentguard.workspace';

function readStored(): string {
  try { return localStorage.getItem(STORAGE_KEY) || ''; } catch { return ''; }
}

export function WorkspaceProvider({children, enabled}: {children: ReactNode; enabled: boolean}) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [workspaceId, setSelected] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const reload = useCallback(() => {
    if (!enabled) { setLoading(false); return; }
    setLoading(true); setError('');
    Promise.all([control<Workspace[]>('v1/workspaces'), control<Environment[]>('v1/environments')])
      .then(([ws, envs]) => {
        setWorkspaces(ws); setEnvironments(envs);
        const stored = readStored();
        setSelected(ws.some(w => w.id === stored) ? stored : ws[0]?.id || '');
      })
      .catch(e => setError(explain(e)))
      .finally(() => setLoading(false));
  }, [enabled]);

  useEffect(reload, [reload]);

  const setWorkspaceId = useCallback((id: string) => {
    setSelected(id);
    try { localStorage.setItem(STORAGE_KEY, id); } catch { /* storage may be blocked */ }
  }, []);

  const value = useMemo(() => ({
    workspaces, workspaceId, setWorkspaceId, loading, error, reload,
    environments: environments.filter(env => env.workspace_id === workspaceId),
  }), [workspaces, environments, workspaceId, setWorkspaceId, loading, error, reload]);

  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useWorkspace(): WorkspaceState {
  const value = useContext(Context);
  if (!value) throw new Error('useWorkspace outside WorkspaceProvider');
  return value;
}
