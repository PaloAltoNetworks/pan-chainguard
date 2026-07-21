#
# Copyright (c) 2026 Palo Alto Networks, Inc.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# SCM API minimal interface for pan-chainguard
# https://pan.dev/scm/docs/home/

import aiohttp
import asyncio
import base64
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import AsyncIterator, Any, Dict, Callable, Tuple, Union, Optional
import ssl
import sys

from . import (DEBUG1, DEBUG2, DEBUG3,
               title, __version__)
from pan_chainguard.scm_error import ParsedResponse

API_URL = 'https://api.strata.paloaltonetworks.com'
OAUTH2_URL = 'https://auth.apps.paloaltonetworks.com'
DEFAULT_LIMIT = 1000  # _all()
TRANSIENT_REQUEST_ERRORS = (
    # XXX version 3.11: This class was made an alias of TimeoutError.
    asyncio.TimeoutError,
)
TRANSIENT_RETRY_DELAY = 1.0

VerifyArg = Optional[Union[bool, str, Path]]


class ApiError(Exception):
    def __init__(self,
                 message: str,
                 *,
                 status: Optional[int] = None,
                 text: Optional[str] = None,
                 parsed: Optional[ParsedResponse] = None) -> None:
        super().__init__(message)
        self.status = status
        self.text = text
        self.parsed = parsed

    @classmethod
    def from_http(cls, status: int, text: str) -> 'ApiError':
        parsed = ParsedResponse(text)
        if parsed.is_json:
            message = 'HTTP %s: %s' % (status, parsed.short_summary())
        else:
            message = 'HTTP %s: %s' % (status, text)
        return cls(message, status=status, text=text, parsed=parsed)


class ArgsError(ApiError):
    pass


class ScmApi:
    def __init__(self, *,
                 tsg_id: Optional[str] = None,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 api_url: Optional[str] = None,
                 oauth2_url: Optional[str] = None,
                 timeout: Optional[Tuple[float, ...]] = None,
                 verify: VerifyArg = None,
                 headers: Optional[dict] = None):
        if tsg_id is None:
            raise ArgsError('tsg_id required')
        if client_id is None:
            raise ArgsError('client_id required')
        if client_secret is None:
            raise ArgsError('client_secret required')

        self.log = logging.getLogger(__name__).log
        self.log(DEBUG2, '%s %s ScmApi',
                 title, __version__)
        self.log(DEBUG2, 'Python %s', sys.version)
        self.log(DEBUG2, 'aiohttp %s', aiohttp.__version__)
        self.api_url = (API_URL if api_url is None
                        else api_url.rstrip('/'))
        self.oauth2_url = (OAUTH2_URL if oauth2_url is None
                           else oauth2_url.rstrip('/'))
        self.ssl_context = None
        if verify is not None:
            self.ssl_context = self._ssl_context(verify)
        self.tsg_id = tsg_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.headers = headers
        self._auth_lock = asyncio.Lock()
        self.timeout = None
        if isinstance(timeout, tuple):
            if len(timeout) == 2:
                self.timeout = aiohttp.ClientTimeout(sock_connect=timeout[0],
                                                     sock_read=timeout[1])
            elif len(timeout) == 1:
                self.timeout = aiohttp.ClientTimeout(total=timeout[0])
            else:
                raise ArgsError('timeout not tuple of length 1-2')
        self.session = None

    async def __aenter__(self):
        self.session = self._session(
            timeout=self.timeout,
            headers=self.headers,
            ssl_context=self.ssl_context,
        )
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    def _ssl_context(self,
                     verify: VerifyArg,
                     ) -> ssl.SSLContext:
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

        if isinstance(verify, bool):
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        elif verify is not None:
            path = Path(verify)
            try:
                if path.is_dir():
                    context.load_verify_locations(capath=path)
                else:
                    context.load_verify_locations(cafile=path)
            except (OSError, ssl.SSLError) as e:
                raise ArgsError(f'{path}: {e}') from e

        return context

    def _session(self, *,
                 timeout: Optional[aiohttp.ClientTimeout] = None,
                 headers: Optional[dict] = None,
                 ssl_context: ssl.SSLContext = None) -> aiohttp.ClientSession:
        def redact_header(name: str, value: str) -> str:
            SENSITIVE_HEADERS = {
                'authorization',
            }
            if name.lower() not in SENSITIVE_HEADERS:
                return value
            parts = value.split(None, 1)
            if len(parts) == 2:
                scheme, _secret = parts
                return f'{scheme} ******'
            return '******'

        async def on_request_start(session, trace_config_ctx, params):
            self.log(DEBUG2, '%s %s', params.method, params.url)
            for k, v in params.headers.items():
                self.log(DEBUG3, '%s: %s', k, redact_header(k, v))

        async def on_request_chunk_sent(session, trace_config_ctx, params):
            if params.chunk:
                self.log(DEBUG3, '%s', params.chunk)

        async def on_request_end(session, trace_config_ctx, params):
            self.log(DEBUG1, '%s %s %s %s %s',
                     params.method,
                     params.url,
                     params.response.status,
                     params.response.reason,
                     params.response.headers.get('content-length'))
            for k, v in params.response.headers.items():
                self.log(DEBUG3, '%s: %s', k, v)

        kwargs = {}
        if headers is not None:
            kwargs['headers'] = headers
        if timeout is not None:
            kwargs['timeout'] = timeout
        if ssl_context is not None:
            kwargs['connector'] = aiohttp.TCPConnector(
                ssl_context=self.ssl_context)

        if (logging.getLogger(__name__).getEffectiveLevel() in
           [DEBUG1, DEBUG2, DEBUG3]):
            trace_config = aiohttp.TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_chunk_sent.append(on_request_chunk_sent)
            trace_config.on_request_end.append(on_request_end)
            kwargs['trace_configs'] = [trace_config]

        return aiohttp.ClientSession(**kwargs)

    def _require_session(self) -> aiohttp.ClientSession:
        if self.session is None:
            raise ApiError('session not initialized; '
                           'use "async with ScmApi()"')
        return self.session

    # https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
    async def client_credentials_grant(self) -> str:
        session = self._require_session()

        data = {
            'grant_type': 'client_credentials',
            'scope': f'tsg_id:{self.tsg_id}',
        }

        auth = aiohttp.BasicAuth(self.client_id, self.client_secret)

        base = '/oauth2/access_token'
        url = f'{self.oauth2_url}{base}'

        async with self.session.post(
                url=url, data=data, auth=auth) as resp:
            text = await resp.text()

            if resp.status != 200:
                raise ApiError(
                    f'OAuth2 token request failed: HTTP {resp.status} {text}'
                )

            try:
                payload = await resp.json()
            except Exception as e:
                raise ApiError(
                    f'OAuth2 token response was not valid JSON: {text}') from e

        x = {k: v for k, v in payload.items() if k not in 'access_token'}
        self.log(DEBUG2, '%s', x)

        access_token = payload.get('access_token')
        if not access_token:
            raise ApiError(f'OAuth2 response missing access_token: {payload}')

        return access_token

    async def _ensure_authorization(self) -> str:
        if self.access_token is not None:
            return self.access_token

        async with self._auth_lock:
            if self.access_token is None:
                self.access_token = await self.client_credentials_grant()

        return self.access_token

    async def _request(self,
                       method: str,
                       path: str,
                       **kwargs) -> aiohttp.ClientResponse:
        session = self._require_session()
        url = self.api_url + path
        base_headers = dict(kwargs.pop('headers', {}))

        retried_auth = False
        retried_transient = False

        while True:
            token = await self._ensure_authorization()

            headers = dict(base_headers)  # copy
            headers['Authorization'] = f'Bearer {token}'

            resp = None
            try:
                resp = await self.session.request(method, url,
                                                  headers=headers, **kwargs)
                # force body read/cache inside retry boundary
                # for possible timeout
                await resp.text()
            except TRANSIENT_REQUEST_ERRORS as e:
                if resp is not None:
                    resp.close()
                if retried_transient:
                    self.log(DEBUG1,
                             'transient API request error after retry: %r', e)
                    raise

                retried_transient = True
                self.log(DEBUG1,
                         'transient API request error: %r; '
                         'retrying once in %.1fs',
                         e, TRANSIENT_RETRY_DELAY)
                await asyncio.sleep(TRANSIENT_RETRY_DELAY)
                continue

            if resp.status != 401:
                return resp

            if retried_auth:
                return resp

            self.log(DEBUG1, '%s', 'access_token expired')
            resp.release()
            self.access_token = None
            retried_auth = True

        raise AssertionError('unreachable')

    async def _all(self, *,
                   func: Callable,
                   item_key: str = 'data',
                   **kwargs) -> AsyncIterator[dict]:
        if 'offset' not in kwargs or kwargs['offset'] is None:
            kwargs['offset'] = 0
        else:
            try:
                kwargs['offset'] = int(kwargs['offset'])
            except (TypeError, ValueError) as e:
                raise ArgsError('offset not int') from e

        if 'limit' not in kwargs or kwargs['limit'] is None:
            kwargs['limit'] = DEFAULT_LIMIT
        else:
            try:
                kwargs['limit'] = int(kwargs['limit'])
            except (TypeError, ValueError) as e:
                raise ArgsError('limit not int') from e

        if kwargs['offset'] < 0:
            raise ArgsError('offset must be >= 0')
        if kwargs['limit'] <= 0:
            raise ArgsError('limit must be > 0')

        seen = kwargs['offset']

        while True:
            resp = await func(**kwargs)
            text = await resp.text()

            if resp.status != 200:
                raise ApiError.from_http(resp.status, text)

            try:
                obj = json.loads(text)
            except ValueError as e:
                raise ApiError(
                    f'Malformed response, invalid JSON: {text}') from e

            try:
                data = obj[item_key]
                total = obj['total']
            except KeyError as e:
                raise ApiError(f'Malformed response, missing key {e}') from e

            if not isinstance(data, list):
                raise ApiError(f'Malformed response, {item_key} is not list')
            if not isinstance(total, int):
                raise ApiError('Malformed response, total is not int')

            current = len(data)

            self.log(DEBUG2, '%s',
                     f'seen {seen} total {total} current {current} '
                     f"offset {kwargs['offset']} limit {kwargs['limit']}")

            if current == 0:
                if seen >= total:
                    break
                raise ApiError(
                    'Malformed response, empty page before total reached')

            for item in data:
                yield item

            seen += current

            if seen >= total:
                break

            kwargs['offset'] += current

    # XXX undocumented, don't depend on this
    # custom role API permission:
    #   prisma_access.config_software_version.read
    async def cloud_version_get(
            self,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/settings'
        path = base + '/software-version'

        params = dict(kwargs.pop('params', {}))

        resp = await self._request('GET', path, params=params, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/identity/list-certificates/
    # custom role API permission:
    #   prisma_access.certificates.read
    async def certificates_get(
            self, *,
            folder: Optional[str] = None,
            snippet: Optional[str] = None,
            limit: Optional[int] = None,
            offset: Optional[int] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/identity/v1'
        path = base + '/certificates'

        params = dict(kwargs.pop('params', {}))
        if folder is not None:
            params['folder'] = folder
        if snippet is not None:
            params['snippet'] = snippet
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset

        resp = await self._request('GET', path, params=params, **kwargs)

        return resp

    async def certificates_get_all(
            self, **kwargs) -> AsyncIterator[dict]:
        folder = kwargs.get('folder')
        async for item in self._all(
                func=self.certificates_get, **kwargs):
            # if folder, only want items for that folder,
            # and not from snippet association
            if folder is not None and (item['folder'] != folder or
                                       item.get('snippet') is not None):
                continue

            yield item

    # https://pan.dev/scm/api/config/ngfw/identity/delete-certificates-by-id/
    # custom role API permission:
    #   prisma_access.certificates.delete
    async def certificate_delete(
            self, *,
            id: Optional[str] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/identity/v1'
        path = base + f'/certificates/{id}'

        resp = await self._request('DELETE', path, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/identity/import-certificates/
    # custom role API permission:
    #   prisma_access.certificates.create
    async def certificate_import(
            self, *,
            name: Optional[str] = None,
            folder: Optional[str] = None,
            snippet: Optional[str] = None,
            certificate_pem: Optional[str] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/identity/v1'
        path = base + '/certificates:import'

        data = {}
        if name is not None:
            data['name'] = name
        if folder is not None:
            data['folder'] = folder
        if snippet is not None:
            data['snippet'] = snippet
        if certificate_pem is not None:
            data['certificate_file'] = base64.b64encode(
                certificate_pem.encode()
            ).decode()
        data['format'] = 'pem'  # XXX

        resp = await self._request('POST', path, json=data, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/security/get-ssl-decryption-settings/
    # custom role API permission:
    #   prisma_access.decryption_policies.read
    async def ssl_decryption_settings_get(
            self, *,
            folder: Optional[str] = None,
            snippet: Optional[str] = None,
            # XXX why API offset, limit here?
            limit: Optional[int] = None,
            offset: Optional[int] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/security/v1'
        path = base + '/ssl-decryption-settings'

        params = dict(kwargs.pop('params', {}))
        if folder is not None:
            params['folder'] = folder
        if snippet is not None:
            params['snippet'] = snippet
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset

        resp = await self._request('GET', path, params=params, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/security/post-ssl-decryption-settings/
    # custom role API permission:
    #   prisma_access.decryption_policies.create
    async def ssl_decryption_settings_create(
            self, *,
            folder: Optional[str] = None,
            snippet: Optional[str] = None,
            data: Optional[str] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/security/v1'
        path = base + '/ssl-decryption-settings'

        empty = {'ssl_decrypt': {}}
        data = dict(data) if data is not None else empty
        if folder is not None:
            data['folder'] = folder
        if snippet is not None:
            data['snippet'] = snippet

        resp = await self._request('POST', path, json=data, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/security/put-ssl-decryption-settings/
    # custom role API permission:
    #   prisma_access.decryption_policies.update
    async def ssl_decryption_settings_replace(
            self, *,
            folder: Optional[str] = None,
            snippet: Optional[str] = None,
            data: Optional[str] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/security/v1'
        path = base + '/ssl-decryption-settings'

        data = dict(data) if data is not None else {}
        if folder is not None:
            data['folder'] = folder
        if snippet is not None:
            data['snippet'] = snippet

        resp = await self._request('PUT', path, json=data, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/setup/list-snippets/
    # custom role API permission:
    #   prisma_access.config_mgmt.read
    async def snippets_list(
            self, *,
            name: Optional[str] = None,
            limit: Optional[int] = None,
            offset: Optional[int] = None,
            **kwargs) -> aiohttp.ClientResponse:
        base = '/config/setup/v1'
        path = base + '/snippets'

        params = dict(kwargs.pop('params', {}))
        if name is not None:
            params['name'] = name
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset

        resp = await self._request('GET', path, params=params, **kwargs)

        return resp

    # https://pan.dev/scm/api/config/ngfw/setup/update-snippet-by-id/
    # custom role API permission:
    #   prisma_access.config_mgmt.update
    async def snippet_replace(
            self, *,
            id: Optional[str] = None,
            name: Optional[str] = None,
            description: Optional[str] = None,
            data: Optional[str] = None,
            **kwargs) -> aiohttp.ClientResponse:

        base = '/config/setup/v1'
        path = base + f'/snippets/{id}'

        data = dict(data) if data is not None else {}
        if name is not None:
            data['name'] = name
        if description is not None:
            data['description'] = description

        resp = await self._request('PUT', path, json=data, **kwargs)

        return resp


@dataclass(frozen=True)
class AccessToken:
    raw: str
    is_jwt: bool = False
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    decode_error: Optional[str] = None

    @classmethod
    def parse(cls, token: str) -> 'AccessToken':
        parts = token.split('.')

        if len(parts) != 3:
            return cls(
                raw=token,
                decode_error=f'not a JWT: expected 3 parts, got {len(parts)}',
            )

        try:
            header = cls._decode_json_part(parts[0])
            payload = cls._decode_json_part(parts[1])
        except ValueError as e:
            return cls(
                raw=token,
                decode_error=f'not a JWT: {e}',
            )

        return cls(
            raw=token,
            is_jwt=True,
            header=header,
            payload=payload,
            signature=parts[2],
        )

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        missing_padding = (-len(s)) % 4
        padded = s + ('=' * missing_padding)
        return base64.urlsafe_b64decode(padded)

    @staticmethod
    def _decode_json_part(part: str) -> Dict[str, Any]:
        import binascii

        try:
            obj = json.loads(AccessToken._b64url_decode(part))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(str(e)) from e

        if not isinstance(obj, dict):
            raise ValueError('JWT part decoded to non-object JSON')

        return obj
