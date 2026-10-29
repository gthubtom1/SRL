"""Validate the stateful MCP HTTP handshake used by the workbench's 2025 clients.

The caller supplies HTTP IO; this module shares response, session and pagination
rules between health checks without treating an open port as a handshake.
"""
from __future__ import annotations

import json
import subprocess
import time

PROTOCOL_VERSIONS = ('2025-06-18', '2024-11-05')
MAX_PAGES = 100
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class McpProbeError(ValueError):
    def __init__(self, stage, message):
        super().__init__(message)
        self.stage = stage


def header_value(headers, name, default=''):
    return next((v for k, v in headers.items() if k.lower() == name.lower()), default)


def config_headers(cfg):
    raw = cfg.get('headers', {})
    if not isinstance(raw, dict):
        raise McpProbeError('config', 'headers 必须是对象')
    headers = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise McpProbeError('config', 'header 名称和值必须是字符串')
        if value.startswith('!'):
            try:
                result = subprocess.run(value[1:], shell=True, capture_output=True,
                                        text=True, timeout=25)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise McpProbeError('config', '动态 header 命令执行失败') from exc
            if result.returncode != 0:
                raise McpProbeError('config', '动态 header 命令退出失败')
            value = result.stdout.strip()
            if not value:
                raise McpProbeError('config', '动态 header 命令没有返回值')
        if any(c in name + value for c in ('\r', '\n', '\x00')):
            raise McpProbeError('config', 'header 含无效控制字符')
        headers[name] = value
    return headers


def _matches_response(message, request_id):
    return (isinstance(message, dict) and message.get('jsonrpc') == '2.0'
            and type(message.get('id')) is type(request_id)
            and message.get('id') == request_id
            and (('result' in message) != ('error' in message)))


def read_response(response, request_id, timeout, max_bytes=MAX_RESPONSE_BYTES):
    """Read finite JSON, or stop SSE as soon as the requested response arrives.

    read1 returns available bytes without waiting for a persistent SSE connection
    to close. Bound both bytes and elapsed time, including streams of heartbeats.
    """
    sse = 'text/event-stream' in response.headers.get('Content-Type', '').lower()
    deadline, total = time.monotonic() + timeout, 0
    chunks, pending, fields = [], b'', []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('MCP HTTP response deadline exceeded')
        # urllib's HTTPResponse exposes its socket here; retain the original
        # socket timeout when an alternative response implementation does not.
        sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
        if sock is not None:
            sock.settimeout(remaining)
        chunk = response.read1(min(65536, max_bytes - total + 1))
        if not chunk:
            return b''.join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError('MCP HTTP response exceeds byte limit')
        chunks.append(chunk)
        if not sse:
            continue
        pending += chunk
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            line = line.rstrip(b'\r')
            if not line:
                if fields:
                    message = json.loads(b'\n'.join(fields).decode('utf-8-sig'))
                    fields = []
                    if _matches_response(message, request_id):
                        return b'data: ' + json.dumps(message).encode('utf-8') + b'\n\n'
            elif line.startswith(b'data:'):
                fields.append(line[5:].removeprefix(b' '))


def parse_rpc(raw, content_type, request_id):
    text = raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw
    if not isinstance(text, str):
        raise ValueError('响应必须是 UTF-8 JSON 或 SSE')
    messages = []
    if 'text/event-stream' in (content_type or '').lower():
        fields = []
        for line in text.splitlines() + ['']:
            if not line:
                if fields:
                    messages.append(json.loads('\n'.join(fields)))
                    fields = []
            elif line.startswith('data:'):
                fields.append(line[5:].removeprefix(' '))
    else:
        messages.append(json.loads(text))
    for message in messages:
        if _matches_response(message, request_id):
            return message
    raise ValueError('未找到匹配请求 id 的 JSON-RPC 响应')


def rpc_result(raw, headers, request_id, stage):
    try:
        message = parse_rpc(raw, header_value(headers, 'content-type'), request_id)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise McpProbeError(stage, '无效 JSON-RPC 响应: %s' % exc) from exc
    if 'error' in message:
        raise McpProbeError(stage, '服务返回 JSON-RPC error')
    if not isinstance(message.get('result'), dict):
        raise McpProbeError(stage, 'result 必须是对象')
    return message['result']


def handshake(post, headers, client_info, versions=PROTOCOL_VERSIONS):
    """post(payload, headers, session) -> (status, response_headers, body)."""
    result, session, last_error = None, None, None
    for version in versions:
        status, received, raw = post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                     'params': {'protocolVersion': version, 'capabilities': {},
                                                'clientInfo': client_info}}, headers, None)
        try:
            if status != 200:
                raise McpProbeError('initialize', 'initialize HTTP %s' % status)
            result = rpc_result(raw, received, 1, 'initialize')
            if (result.get('protocolVersion') not in versions
                    or not isinstance(result.get('capabilities'), dict)
                    or not isinstance(result.get('serverInfo'), dict)
                    or not isinstance(result['serverInfo'].get('name'), str)
                    or not isinstance(result['serverInfo'].get('version'), str)):
                raise McpProbeError('initialize', 'initialize 缺有效版本、能力或服务身份')
            session = header_value(received, 'mcp-session-id') or None
            break
        except McpProbeError as exc:
            result, last_error = None, exc
            if status in (401, 403):
                break
    if result is None:
        raise last_error or McpProbeError('initialize', 'initialize 未成功')

    negotiated = dict(headers)
    negotiated['MCP-Protocol-Version'] = result['protocolVersion']
    status, _, _ = post({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, negotiated, session)
    if not 200 <= status < 300:
        raise McpProbeError('initialized', 'notifications/initialized HTTP %s' % status)
    tools, cursor, seen = [], None, set()
    for page in range(MAX_PAGES):
        params = {'cursor': cursor} if cursor is not None else {}
        rid = page + 2
        status, received, raw = post({'jsonrpc': '2.0', 'id': rid, 'method': 'tools/list',
                                     'params': params}, negotiated, session)
        if status != 200:
            raise McpProbeError('tools', 'tools/list HTTP %s' % status)
        listed = rpc_result(raw, received, rid, 'tools')
        batch = listed.get('tools')
        if not isinstance(batch, list) or any(
                not isinstance(t, dict) or not isinstance(t.get('name'), str) or not t['name']
                for t in batch):
            raise McpProbeError('tools', 'tools/list 缺有效 tools 数组')
        tools.extend(batch)
        cursor = listed.get('nextCursor')
        if cursor is None:
            return {'serverInfo': result['serverInfo'], 'protocolVersion': result['protocolVersion'],
                    'tools': tools}
        if not isinstance(cursor, str) or not cursor or cursor in seen:
            raise McpProbeError('tools', 'tools/list 无效或重复分页 cursor')
        seen.add(cursor)
    raise McpProbeError('tools', 'tools/list 超过 %d 页上限' % MAX_PAGES)


def probe_endpoint(cfg):
    """Independent HTTP/SSE handshake; never claims host-session registration."""
    try:
        from urllib.parse import urlparse
        if not isinstance(cfg, dict):
            raise McpProbeError('config', '探测配置必须是对象')
        url, transport = cfg.get('url'), cfg.get('transport', 'http')
        parsed = urlparse(url) if isinstance(url, str) else None
        if (not parsed or parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username or parsed.password or parsed.fragment
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise McpProbeError('config', 'url 必须是有效 HTTP(S) 地址')
        timeout = cfg.get('timeout', 8)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise McpProbeError('config', 'timeout 必须在 0 到 60 秒之间')
        headers = config_headers(cfg)
        if transport in ('http', 'streamable-http'):
            import urllib.error
            import urllib.request
            deadline = time.monotonic() + timeout

            def post(payload, negotiated, session):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('MCP handshake deadline exceeded')
                sent = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
                sent.update(negotiated)
                if session:
                    sent['Mcp-Session-Id'] = session
                request = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                                 method='POST', headers=sent)
                try:
                    with urllib.request.urlopen(request, timeout=remaining) as response:
                        return response.status, dict(response.headers), read_response(
                            response, payload.get('id'), max(.001, deadline - time.monotonic()))
                except urllib.error.HTTPError as exc:
                    with exc:
                        return exc.code, dict(exc.headers), b''

            result = handshake(post, headers, {'name': 'seep-endpoint-probe', 'version': '1'})
            count, info, version = len(result['tools']), result['serverInfo'], result['protocolVersion']
        elif transport == 'sse':
            import anyio
            from mcp import ClientSession
            from mcp.client.sse import sse_client

            async def probe_sse():
                with anyio.fail_after(timeout):
                    async with sse_client(url, headers=headers, timeout=timeout,
                                          sse_read_timeout=timeout) as streams:
                        async with ClientSession(*streams) as session:
                            initialized = await session.initialize()
                            count, cursor, seen = 0, None, set()
                            for _ in range(MAX_PAGES):
                                page = await session.list_tools(cursor=cursor)
                                count += len(page.tools)
                                cursor = page.nextCursor
                                if cursor is None:
                                    return count, initialized.serverInfo.model_dump(), initialized.protocolVersion
                                if not isinstance(cursor, str) or not cursor or cursor in seen:
                                    raise McpProbeError('tools', 'tools/list 无效或重复分页 cursor')
                                seen.add(cursor)
                            raise McpProbeError('tools', 'tools/list 超过分页上限')

            count, info, version = anyio.run(probe_sse)
        else:
            raise McpProbeError('config', '不支持的 endpoint transport')
        return {'ok': True, 'stage': 'tools', 'tools': count, 'serverInfo': info,
                'protocolVersion': version, 'session_verified': False}
    except McpProbeError as exc:
        return {'ok': False, 'stage': exc.stage, 'error': str(exc), 'session_verified': False}
    except Exception as exc:
        # Transport exceptions can contain a URL or credentials. Expose type only.
        return {'ok': False, 'stage': 'handshake', 'error': type(exc).__name__, 'session_verified': False}


def _cli():
    import argparse
    parser = argparse.ArgumentParser(description='独立 MCP HTTP/SSE 握手验证')
    parser.add_argument('--request-file', required=True)
    args = parser.parse_args()
    try:
        with open(args.request_file, encoding='utf-8-sig') as stream:
            result = probe_endpoint(json.load(stream))
    except (OSError, ValueError) as exc:
        result = {'ok': False, 'stage': 'config', 'error': type(exc).__name__, 'session_verified': False}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(_cli())
