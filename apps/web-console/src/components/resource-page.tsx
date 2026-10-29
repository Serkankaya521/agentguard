'use client';
import {useEffect, useState} from 'react';
import {Empty, ErrorNote, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Row} from '@/lib/control';

const HIDDEN = new Set(['document', 'metadata', 'attributes', 'source_document', 'compiled_artifact', 'tenant_id']);

function cellValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function Listing({path}: {path: string}) {
  const [rows, setRows] = useState<Row[]>();
  const [error, setError] = useState('');
  useEffect(() => { setRows(undefined); control<Row[]>(path).then(setRows).catch(e => setError(explain(e))); }, [path]);
  if (error) return <ErrorNote message={error}/>;
  if (!rows) return <p className="muted">Loading…</p>;
  if (!rows.length) return <div className="panel"><Empty title="Nothing here yet"/></div>;
  const columns = Array.from(new Set(rows.flatMap(row => Object.keys(row)))).filter(k => !HIDDEN.has(k)).slice(0, 7);
  return <div className="table-wrap"><table>
    <thead><tr>{columns.map(c => <th key={c}>{c.replaceAll('_', ' ')}</th>)}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={String(row.id ?? i)}>{columns.map(c =>
      <td key={c} className={c.endsWith('id') ? 'hash' : ''}>{cellValue(row[c])}</td>)}</tr>)}</tbody>
  </table></div>;
}

/** Generic read-only listing. `path` receives the selected workspace when `scoped` is true. */
export function ResourcePage({title, description, path, scoped = true}:
  {title: string; description: string; path: string; scoped?: boolean}) {
  return <>
    <PageHead title={title} description={description}/>
    {scoped
      ? <RequireWorkspace>{workspaceId =>
          <Listing path={`${path}${path.includes('?') ? '&' : '?'}workspace_id=${encodeURIComponent(workspaceId)}`}/>}</RequireWorkspace>
      : <Listing path={path}/>}
  </>;
}
