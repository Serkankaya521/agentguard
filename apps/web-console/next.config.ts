import type { NextConfig } from 'next';

const config: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  agentRules: false,
  async headers() {
    const scripts=process.env.NODE_ENV==='production' ? "script-src 'self'" : "script-src 'self' 'unsafe-eval'";
    return [{source:'/(.*)',headers:[
      {key:'Content-Security-Policy',value:`default-src 'self'; ${scripts}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`},
      {key:'Referrer-Policy',value:'no-referrer'},
      {key:'X-Content-Type-Options',value:'nosniff'},
      {key:'Permissions-Policy',value:'camera=(), microphone=(), geolocation=()'},
    ]}];
  },
};
export default config;
