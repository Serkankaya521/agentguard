'use client';
import {useEffect,useState} from 'react';
import {control,Row} from '@/lib/control';

export function ResourcePage({title,path,description}:{title:string;path:string;description:string}){
  const [rows,setRows]=useState<Row[]>([]),[error,setError]=useState(''),[loading,setLoading]=useState(true);
  useEffect(()=>{control<Row[]>(path).then(setRows).catch(e=>setError(e.message)).finally(()=>setLoading(false))},[path]);
  const columns=Array.from(new Set(rows.flatMap(row=>Object.keys(row)))).filter(k=>!['document','metadata','attributes'].includes(k)).slice(0,7);
  return <><div className="eyebrow">Control plane</div><h1>{title}</h1><p className="lede">{description}</p>
    {loading&&<p className="muted">Loading tenant-scoped data…</p>}{error&&<p className="error">{error}</p>}
    {!loading&&!error&&<table><thead><tr>{columns.map(c=><th key={c}>{c.replaceAll('_',' ')}</th>)}</tr></thead>
    <tbody>{rows.map((row,i)=><tr key={String(row.id||i)}>{columns.map(c=><td key={c}>{typeof row[c]==='object'?JSON.stringify(row[c]):String(row[c]??'')}</td>)}</tr>)}</tbody></table>}
  </>
}
