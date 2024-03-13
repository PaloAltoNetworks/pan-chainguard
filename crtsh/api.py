#
# Copyright (c) 2024 Palo Alto Networks, Inc.
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

# crt.sh API interface

import aiohttp
import asyncio

URL = 'https://crt.sh'


class ArgsError(Exception):
    pass


class CrtShApi:
    def __init__(self, *,
                 timeout=None,
                 headers=None):
        self.url = URL

        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                raise ArgsError('timeout tuple length must be 2')
            x = aiohttp.ClientTimeout(sock_connect=timeout[0],
                                      sock_read=timeout[1])
        else:
            x = aiohttp.ClientTimeout(total=timeout)

        self.session = aiohttp.ClientSession(timeout=x,
                                             headers=headers)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    async def content(self, *, resp=None):
        if resp is None:
            raise ArgsError('missing resp')

        if resp.status != 200:
            return None, None

        filename = None
        if (resp.content_disposition is not None and
           resp.content_disposition.filename is not None):
            filename = resp.content_disposition.filename

        x = await resp.text()

        return filename, x

    async def download(self, *,
                       id=None,
                       query_string=None):
        path = '/'
        url = self.url + path

        data = {}
        if id is not None:
            data['d'] = id
        if query_string is not None:
            data.update(query_string)

        kwargs = {
            'url': url,
            'data': data,
        }

        resp = await self.session.post(**kwargs)

        return resp
