"""Explicit future operator mode. Never selected by the offline worker."""
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def validate_external(mode, endpoint, token_file, allow_external):
    if mode == 'in-memory':
        if endpoint or token_file or allow_external:
            raise ValueError('offline mode refuses external endpoint or authorization options')
        return
    if mode != 'external-host' or not allow_external:
        raise ValueError('external-host requires the operator to explicitly select --allow-external')
    parsed = urllib.parse.urlsplit(endpoint or '')
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.path != '/mcp' or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('external-host requires an exact HTTPS Connector URL ending in /mcp')
    if not token_file:
        raise ValueError('external-host requires a private token file; tokens are never flags')

def rpc(opener, endpoint, token, call_id, method, params):
    message = {'jsonrpc': '2.0', 'method': method, 'params': params}
    if call_id is not None:
        message['id'] = call_id
    body = json.dumps(message).encode()
    request = urllib.request.Request(endpoint, body, headers={
        'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
        'Mcp-Protocol-Version': '2025-11-25', 'Authorization': 'Bearer ' + token,
    })
    try:
        with opener.open(request, timeout=15) as response:
            data = response.read(1048577)
            media = response.headers.get_content_type()
            status = response.status
            if len(data) > 1048576:
                raise ValueError('incomplete_response')
    except urllib.error.HTTPError as error:
        code = 'access_denied' if error.code in (401, 403) else ('wrong_endpoint' if error.code == 404 else 'service_unavailable')
        raise ValueError(code) from None
    except (OSError, urllib.error.URLError):
        raise ValueError('service_unavailable') from None
    if call_id is None:
        if status != 202 or data:
            raise ValueError('protocol_error')
        return {}
    if media == 'text/event-stream':
        if not data.endswith(b'\n\n') and not data.endswith(b'\r\n\r\n'):
            raise ValueError('incomplete_response')
        frames = [line[5:].lstrip(b' ') for line in data.splitlines() if line.startswith(b'data:')]
        if len(frames) != 1:
            raise ValueError('incomplete_response')
        data = frames[0]
    elif media != 'application/json':
        raise ValueError('protocol_error')
    try:
        envelope = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('incomplete_response') from None
    if envelope.get('id') != call_id or envelope.get('jsonrpc') != '2.0' or envelope.get('error'):
        raise ValueError('protocol_error')
    result = envelope.get('result')
    if not isinstance(result, dict) or result.get('isError'):
        raise ValueError('tool_error')
    return result

def external_reads(endpoint, token_file):
    # Explicit selection and URL validation happen before this function is called.
    path = Path(token_file)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError('authorization file must be private and not a symlink')
    token = path.read_text().strip()
    if not token.startswith('tunn_mcp_') or len(token) > 4096:
        raise ValueError('invalid authorization file')
    opener = urllib.request.build_opener(NoRedirect())
    rpc(opener, endpoint, token, 1, 'initialize', {'protocolVersion': '2025-11-25',
        'capabilities': {}, 'clientInfo': {'name': 'wave8-finite-consumer', 'version': '1'}})
    rpc(opener, endpoint, token, None, 'notifications/initialized', {})
    rpc(opener, endpoint, token, 2, 'tools/list', {})
    listed = rpc(opener, endpoint, token, 3, 'tools/call', {'name': 'project_list', 'arguments': {}})
    manifest = listed.get('structuredContent', {}).get('files', [])
    if not (0 < len(manifest) <= 32):
        raise ValueError('invalid manifest')
    reads = []
    for call_id, entry in enumerate(manifest, 4):
        if not (1 <= entry.get('lines', 0) <= 32):
            raise ValueError('operator fixture exceeds finite read contract')
        result = rpc(opener, endpoint, token, call_id, 'tools/call', {'name': 'project_read',
            'arguments': {'path': entry['path'], 'firstLine': 1, 'lastLine': entry['lines']}})
        evidence = result.get('structuredContent', {})
        if evidence.get('status') != 'ok' or evidence.get('truncated'):
            raise ValueError('incomplete_response')
        reads.extend(evidence.get('spans', []))
    # No endpoint, token, request headers or arbitrary prompts enter the receipt.
    return {'scope': 'operator-fixture', 'files': manifest, 'reads': reads,
            'protocol': '2025-11-25', 'transport': 'explicit external HTTPS'}
