from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]


def test_web_console_keeps_credentials_out_of_browser_storage_and_bounds_proxy():
    session=(ROOT/'apps/web-console/src/app/api/session/route.ts').read_text(encoding='utf-8')
    proxy=(ROOT/'apps/web-console/src/app/api/control/[...path]/route.ts').read_text(encoding='utf-8')
    client=''.join(path.read_text(encoding='utf-8') for path in
                   (ROOT/'apps/web-console/src').rglob('*.tsx'))
    assert 'httpOnly:true' in session and "sameSite:'strict'" in session
    assert 'ORIGIN_POLICY_MISSING' in session and 'PAYLOAD_TOO_LARGE' in session
    assert 'ORIGIN_POLICY_MISSING' in proxy and 'PAYLOAD_TOO_LARGE' in proxy
    assert 'NEXT_PUBLIC_' not in session+proxy+client
    assert 'localStorage' not in session+proxy+client
