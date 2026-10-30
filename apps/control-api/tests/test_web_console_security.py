import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]


def test_web_console_keeps_credentials_out_of_browser_storage_and_bounds_proxy():
    session=(ROOT/'apps/web-console/src/app/api/session/route.ts').read_text(encoding='utf-8')
    proxy=(ROOT/'apps/web-console/src/app/api/control/[...path]/route.ts').read_text(encoding='utf-8')
    src=ROOT/'apps/web-console/src'
    # UI code = everything except the server-side credential boundary (src/app/api/*).
    api_dir=src/'app'/'api'
    ui=''.join(path.read_text(encoding='utf-8')
               for path in sorted(src.rglob('*.ts'))+sorted(src.rglob('*.tsx'))
               if api_dir not in path.parents)
    assert 'httpOnly:true' in session and "sameSite:'strict'" in session
    assert 'ORIGIN_POLICY_MISSING' in session and 'PAYLOAD_TOO_LARGE' in session
    assert 'ORIGIN_POLICY_MISSING' in proxy and 'PAYLOAD_TOO_LARGE' in proxy
    assert 'NEXT_PUBLIC_' not in session+proxy+ui
    # The session token lives only in the httpOnly cookie, never in JS-readable storage.
    # The credential-handling routes never touch browser storage...
    assert 'localStorage' not in session+proxy and 'sessionStorage' not in session+proxy
    # ...the token cookie name is never referenced from UI code...
    assert 'agentguard_session' not in ui
    # ...and no credential-like value is ever written to browser storage. localStorage is
    # otherwise permitted only for non-credential UI preferences (selected workspace, language).
    assert not re.search(r'(local|session)Storage[^\n;]{0,80}(token|secret|password|credential|authorization|api[_-]?key)',
                         ui, re.IGNORECASE)
