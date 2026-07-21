#!/usr/bin/env python3

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

import argparse
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum, auto
import json
import logging
import os
from pathlib import Path
import pprint
import re
import sys
import time
from treelib import Node, Tree
import traceback
from typing import Tuple, Union

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import (title, __version__, user_agent,
                            DEBUG1, DEBUG2, DEBUG3)
from pan_chainguard.scm_api import (ScmApi, ApiError, ArgsError,
                                    AccessToken,
                                    API_URL, OAUTH2_URL)
from pan_chainguard.scm_error import ParsedResponse
import pan_chainguard.util

# use 63 length name
NAME_RE = pan_chainguard.util.NAME_RE_SCM

args = None


class Description(Enum):
    UNSPECIFIED = auto()
    NO_ARGUMENT = auto()


def main():
    global args
    args = parse_args()

    if args.debug:
        logger = logging.getLogger()
        if args.debug == 3:
            logger.setLevel(DEBUG3)
        elif args.debug == 2:
            logger.setLevel(DEBUG2)
        elif args.debug == 1:
            logger.setLevel(DEBUG1)

        log_format = '%(message)s'
        if args.dtime:
            log_format = '%(asctime)s ' + log_format
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    ret = asyncio.run(main_loop())

    sys.exit(ret)


async def main_loop():
    oauth_args = credentials(args.credentials)
    if args.debug:
        for k in ['tsg_id', 'client_id']:
            print(k, oauth_args[k], file=sys.stderr)

    headers = {'user-agent': user_agent}
    try:
        async with ScmApi(
                headers=headers,
                api_url=args.api_url,
                oauth2_url=args.oauth2_url,
                timeout=args.timeout,
                verify=args.verify,
                **oauth_args) as scm:

            if args.jwt:
                resp = await scm.cloud_version_get()
                if scm.access_token is None:
                    print("Can't get access_token", file=sys.stderr)
                    return 1

                token = AccessToken.parse(scm.access_token)
                if token.is_jwt:
                    print('header:',
                          json.dumps(token.header, indent=2, sort_keys=True))
                    print('payload:',
                          json.dumps(token.payload, indent=2, sort_keys=True))
                    if args.verbose:
                        print('signature: "%s"' % token.signature)
                    else:
                        print('signature length:', len(token.signature))
                else:
                    print('opaque token or invalid JWT:', token.decode_error)
                return 0

            if args.debug:
                resp = await scm.cloud_version_get()
                if resp.status == 200:
                    x = await resp.json()
                    if 'software_version' in x:
                        print('Cloud Management Version',
                              x['software_version'], file=sys.stderr)

            if any([args.show, args.show_tree,
                    args.update_trusted, args.delete, args.update]):
                data = await get_certs(scm)
                if args.debug > 2 and data:
                    print(pprint.pformat(data), file=sys.stderr)

            if args.show:
                await show(scm, data)

            if args.show_tree:
                await show_tree(scm, data)

            if args.update_trusted:
                await update_trusted_root_cas(scm, data.keys(), quiet=False)

            total = 0
            if args.delete:
                total += await delete_certs(scm, data)
                if total and args.update:
                    data = await get_certs(scm)

            if args.update:
                if args.certs is None:
                    print('--certs argument required', file=sys.stderr)
                    return 1
                if args.type is None:
                    print('--type argument required', file=sys.stderr)
                    return 1

                total += await update_certs(scm, data)

            if (total and args.snippet is not None and
               args.description is not Description.UNSPECIFIED):
                await update_description(scm)

    except (ArgsError, ApiError, Exception) as e:
        print_exception(e, args.debug)
        return 1

    return 0


def credentials(path: Path) -> dict:
    data = load_json_file(path)
    required = ['tsg_id', 'client_id', 'client_secret']
    missing = set(required) - data.keys()
    if missing:
        print(f'{path}: missing keys: {", ".join(sorted(missing))}',
              file=sys.stderr)
        sys.exit(1)
    extra = data.keys() - set(required)
    if extra:
        print(f'{path}: extra keys: {", ".join(sorted(extra))}',
              file=sys.stderr)
        sys.exit(1)

    return data


def load_json_file(path: Path) -> dict:
    try:
        with path.open('r') as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print('%s: %s' % (path, e), file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print(f'{path}: JSON is not an object; got {type(data).__name__}',
              file=sys.stderr)
        sys.exit(1)

    return data


def exclude_cert(sha256):
    EXCLUDE = [
        # XXX Signature Algorithm: rsassaPss
        '233525D6E906A9B99176204E3C2B4FBF5CEE03F2D126B2E64428BDF97CBC6138',
    ]

    if sha256 in EXCLUDE:
        if args.debug:
            print('Skip problem certificate %s' % sha256, file=sys.stderr)
        return True

    return False


async def get_certs(scm):
    data = {}
    prog = re.compile(NAME_RE)
    progcn = re.compile(r'/CN=((?:\\.|[^/\\])*)(?=/|$)')

    async for item in scm.certificates_get_all(
            folder=args.folder,
            snippet=args.snippet):
        if args.debug > 2:
            print(pprint.pformat(item), file=sys.stderr)

        name = item['name']
        if not prog.search(name):
            continue

        subject = item['subject']
        subject_cn = None
        match = progcn.search(subject)
        if match:
            subject_cn = re.sub(r'\\(.)', r'\1', match.group(1))
        issuer = item['issuer']
        issuer_cn = None
        match = progcn.search(issuer)
        if match:
            issuer_cn = match.group(1)
            issuer_cn = re.sub(r'\\(.)', r'\1', match.group(1))
        expiry = item['expiry_epoch']
        try:
            if time.time() > int(expiry):
                expired = True
            else:
                expired = False
        except ValueError as e:
            print('%s expiry_epoch %s: %s' % (
                name, expiry, e), file=sys.stderr)

        v = {
            'cert-name': name,
            'id':  item['id'],
            'subject': subject,
            'subject-cn': subject_cn,
            'subject-hash': item['subject_hash'],
            'issuer': issuer,
            'issuer-cn': issuer_cn,
            'issuer-hash': item['issuer_hash'],
            'expired': expired,
        }
        data[name] = v

    return data


async def delete_certs(scm, data) -> int:
    if args.dry_run:
        print('delete dry-run: %d to delete' % len(data))
        return 0

    if data:
        obj = await get_decryption_settings(scm)
        all_trusted = get_trusted_root_cas(obj)
        current, other = get_managed_trusted_root_cas(all_trusted)

        to_delete = data.keys()
        new = list(set(current) - set(to_delete))
        if args.debug > 1:
            print('new trusted', pprint.pformat(new), file=sys.stderr)

        await update_trusted_root_cas(scm, new)

        for name in data:
            await delete_cert(scm, len(data), name, data[name]['id'])

    print('%d certificates deleted' % len(data))
    return len(data)


async def delete_cert(scm, total, name, id):
    kwargs = {'id': id}
    resp = await api_request(scm.certificate_delete, kwargs)

    try:
        delete_cert.count += 1
    except AttributeError:
        delete_cert.count = 1

    if args.verbose:
        print('deleted %s %d/%d' % (
            name,
            delete_cert.count,
            total), file=sys.stderr)


async def get_decryption_settings(scm):
    kwargs = {
        'folder': args.folder,
        'snippet': args.snippet,
    }
    resp = await api_request(scm.ssl_decryption_settings_get, kwargs)
    data = await resp.json()
    if args.debug > 1:
        print(pprint.pformat(data), file=sys.stderr)

    # Identify cases for no settings object, so it can be created
    # 1) newly created folder: will inherit settings from parent
    if (args.folder and data['data'] and
       data['data'][0]['folder'] != args.folder):
        return

    # 2) newly created snippet: will not have a settings object
    # {'data': [], 'limit': 200, 'offset': 0, 'total': 0}
    if not data['data']:
        return

    obj = data['data'][0]['ssl_decrypt']
    return obj


def get_trusted_root_cas(obj):
    return [] if obj is None else obj.get('trusted_root_CA', [])


def get_managed_trusted_root_cas(trusted_root_cas):
    prog = re.compile(NAME_RE)
    current = []
    other = []

    for name in trusted_root_cas:
        if prog.search(name):
            current.append(name)
        else:
            other.append(name)

    return current, other


async def update_trusted_root_cas(scm, new, quiet=True):
    settings = await get_decryption_settings(scm)
    if settings is None and not args.dry_run:
        # Settings object does not exist, create empty object.
        kwargs = {
            'folder': args.folder,
            'snippet': args.snippet,
        }
        resp = await api_request(scm.ssl_decryption_settings_create,
                                 kwargs, [201])
        settings = await get_decryption_settings(scm)

    all_trusted = get_trusted_root_cas(settings)
    current, other = get_managed_trusted_root_cas(all_trusted)

    add = set(new) - set(current)
    delete = set(current) - set(new)

    if args.debug > 1:
        for name, items in (
                ('delete', delete),
                ('add', add)):
            print(f'update trusted {name} {len(items)}', file=sys.stderr)
            if args.debug > 2:
                print(f'update trusted {name}', pprint.pformat(items),
                      file=sys.stderr)

    if args.dry_run:
        print('update-trusted dry-run: %d certificates'
              ' to enable as trusted root CAs' % len(add))
        return

    if add or delete:
        new_all = set(other) | set(new)
        settings['trusted_root_CA'] = list(new_all)
        data = {'ssl_decrypt': settings}
        kwargs = {
            'folder': args.folder,
            'snippet': args.snippet,
            'data': data,
        }
        resp = await api_request(scm.ssl_decryption_settings_replace, kwargs)

    if not quiet:
        print('%d certificates enabled as trusted root CA' % len(add))


async def update_certs(scm, old) -> int:
    new = {}
    try:
        data = pan_chainguard.util.read_cert_archive(
            path=args.certs)
    except pan_chainguard.util.UtilError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    for sha256 in data:
        if exclude_cert(sha256):
            continue
        cert_type, content = data[sha256]
        if cert_type not in args.type:
            continue
        cert_name = pan_chainguard.util.hash_to_name_scm(sha256=sha256)
        new[cert_name] = content

    old_set = set(old.keys())
    new_set = set(new.keys())

    if args.debug > 2:
        print('old', pprint.pformat(old_set), file=sys.stderr)
        print('new', pprint.pformat(new_set), file=sys.stderr)

    delete = list(old_set - new_set)
    add = list(new_set - old_set)
    keep = list(old_set - set(delete))

    if args.debug > 1:
        for name, items in (
                ('delete', delete),
                ('add', add),
                ('keep', keep)):
            print(f'update {name} {len(items)}', file=sys.stderr)
            if args.debug > 2:
                print(f'update {name}', pprint.pformat(items), file=sys.stderr)

    if args.dry_run:
        print('update dry-run: %d to delete, %d to add' % (
            len(delete), len(add)))
        return 0

    delete_data = {k: v for k, v in old.items() if k in delete}
    total_delete = await delete_certs(scm, delete_data)

    total_add = 0
    for name in add:
        if await add_cert(scm, len(add), name, new[name]):
            total_add += 1

    if total_add:
        new = add_cert.cert_names + keep
        await update_trusted_root_cas(scm, new)

    print('%d certificates added' % total_add)
    return total_delete + total_add


async def add_cert(scm, total, cert_name, content):
    kwargs = {
        'name': cert_name,
        'folder': args.folder,
        'snippet': args.snippet,
        'certificate_pem': content.decode(),
    }
    SKIP_ERRORS = [
        'Certificate is expired',
        'Unsupported digest or keys used in FIPS-CC mode',
        'Failed to create xml node.',
    ]

    resp = await api_request(scm.certificate_import, kwargs, [200, 400])
    if resp.status == 400:
        text = await resp.text()
        r = ParsedResponse(text)
        for error in SKIP_ERRORS:
            if error in r.raw:
                if args.verbose:
                    print('%s skipped: %s' % (cert_name, r.short_summary()),
                          file=sys.stderr)
                return False
        e = r.summary() if args.debug else r.short_summary()
        print('%s: %s: HTTP %s %s' %
              (scm.certificate_import.__name__, kwargs, resp.status, e),
              file=sys.stderr)
        sys.exit(1)

    # Use function attribute to cache certificate names so we can use
    # a single API request to enable them as trusted root CAs.
    try:
        add_cert.cert_names.append(cert_name)
    except AttributeError:
        add_cert.cert_names = [cert_name]

    if args.verbose:
        print('added %s %d/%d' % (
            cert_name,
            len(add_cert.cert_names),
            total), file=sys.stderr)

    return True


async def update_description(scm):
    kwargs = {'name': args.snippet}
    resp = await api_request(scm.snippets_list, kwargs, [200, 403])
    if resp.status == 403:
        print(("Warning: Can't get snippet to update description "
               "(API service account permission problem?)"))
        return

    data = await resp.json()
    if args.debug > 1:
        print(pprint.pformat(data), file=sys.stderr)

    if args.description is Description.NO_ARGUMENT:
        now_utc = datetime.now(timezone.utc)
        date_str = now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
        description = f'{user_agent} updated {date_str}'
    else:
        description = args.description

    kwargs = {
        'id': data['id'],
        'name': args.snippet,
        'description': description,
    }
    resp = await api_request(scm.snippet_replace, kwargs)

    print(f'snippet description updated: "{description}"')


async def show(scm, data):
    out = []
    num_expired = 0

    for x in data:
        expired = ''
        if data[x]['expired']:
            num_expired += 1
            expired = ' (expired)'
        if data[x]['subject'] == data[x]['issuer']:
            # Root
            # XXX subject == issuer can be an intermediate
            type_ = 'R'
        else:
            # Intermediate
            type_ = 'I'
        m = '%s %s%s Subject: "%s" Issuer: "%s"' % (
            x, type_, expired,
            data[x]['subject'], data[x]['issuer'])
        out.append(m)

    expired = ''
    if num_expired:
        expired = ' (%d expired)' % num_expired
    print('%d Custom Certificates%s' % (len(out), expired))
    if out and args.verbose:
        print('\n'.join(out))

    if out:
        obj = await get_decryption_settings(scm)
        all_trusted = get_trusted_root_cas(obj)
        current, other = get_managed_trusted_root_cas(all_trusted)
        num = len(current)
        print('%d Trusted Root CA Certificates' % num)
        if num < len(out):
            print('Warning: %d certificates not trusted; '
                  'run bashguard.py --update-trusted' % (len(out) - num))


def duplicates_in_path(tree: Tree) -> list[dict]:
    def dfs(nid: str, seen: set[str], out: list[dict]) -> None:
        new_seen = set(seen)
        node = tree.get_node(nid)
        if node.tag != 'Root':
            key = node.data['subject-hash']

            if key in seen:
                out.append({
                    'node-id': nid,
                    'tag': str(node.tag),
                    'key': key,
                    'node-data': node.data,
                })
                return  # stop this root-to-leaf path here

            else:
                new_seen.add(key)

        children = tree.children(nid)
        if not children:
            return  # leaf reached, no dup on this path

        for child in children:
            dfs(child.identifier, new_seen, out)

    duplicates = []
    dfs(tree.root, set(), duplicates)

    return duplicates


async def show_tree(scm, data):
    issuers = defaultdict(list)
    subjects = defaultdict(list)
    roots = []

    for x in data:
        issuers[data[x]['issuer-hash']].append(data[x])
        subjects[data[x]['subject-hash']].append(data[x])
        if data[x]['subject-hash'] == data[x]['issuer-hash']:
            roots.append(data[x])

    orphans = []

    for x in data:
        if data[x]['issuer-hash'] not in subjects:
            orphans.append(data[x])

    if args.debug:
        print('issuers', pprint.pformat(issuers), file=sys.stderr)
        print('subjects', pprint.pformat(subjects), file=sys.stderr)
        print('roots', pprint.pformat(roots), file=sys.stderr)
        print('orphans', pprint.pformat(orphans), file=sys.stderr)

    tree = Tree()
    tree.add_node(Node(tag='Root', identifier=0))

    def build_node(x):
        subject = x['subject-cn'] if x['subject-cn'] else x['subject']
        issuer = x['issuer-cn'] if x['issuer-cn'] else x['issuer']
        tag = (f"{x['cert-name']} "
               f'Subject: "{subject}" '
               f'Issuer: "{issuer}"')

        node = Node(tag=tag, identifier=x['cert-name'], data=x)

        return node

    def add_children(parent, issuer):
        if issuer in issuers:
            for x in issuers[issuer]:
                if (tree.contains(x['cert-name']) or
                   x['subject-hash'] == x['issuer-hash']):
                    continue

                tree.add_node(build_node(x), parent=parent)
                add_children(x['cert-name'], x['subject-hash'])

    def format_stats(tree):
        stats = pan_chainguard.util.stats_from_tree(tree=tree)

        for k, v in stats.items():
            name = k.replace('_', ' ').title()
            value = '%.4f' % v if isinstance(v, float) else '%d' % v
            print('%s: %s' % (name, value))

    for x in roots + orphans:
        tree.add_node(build_node(x), parent=0)
        add_children(x['cert-name'], x['subject-hash'])

    print(tree.show(stdout=False), end='')

    if args.verbose:
        format_stats(tree)

    duplicates = duplicates_in_path(tree)
    if args.verbose and duplicates:
        print(f'Info: {len(duplicates)} duplicate subject in tree path')
        for x in duplicates:
            print(f"{x['key']} {x['tag']}")

    treelen = len(tree) - 1  # don't count root node
    sublen = 0
    for x in subjects:
        sublen += len(subjects[x])
    if treelen != sublen:
        print('Error: tree length != number of certificates:'
              ' %d != %d' % (treelen, sublen))

    duplicates = []
    for x in subjects:
        if len(subjects[x]) > 1:
            duplicates.append(subjects[x][0]['subject'])

    if args.verbose and duplicates:
        print('Info: %d duplicate certificate subjects' %
              len(duplicates))
        print('\n'.join(duplicates))


def print_exception(exc, debug):
    limit = 0
    if debug == 1:
        limit = -1
    elif debug > 1:
        limit = None
    x = traceback.format_exception(None, exc, exc.__traceback__, limit=limit)
    print(''.join(x), end='', file=sys.stderr)


async def api_request(func, kwargs, status=None):
    if status is None:
        status = [200]
    resp = await func(**kwargs)
    if resp.status not in status:
        text = await resp.text()
        r = ParsedResponse(text)
        e = r.summary() if args.debug else r.short_summary()
        print('%s: %s: HTTP %s %s' %
              (func.__name__, kwargs, resp.status, e),
              file=sys.stderr)
        sys.exit(1)

    return resp


def parse_args():
    def existing_file(value: str) -> Path:
        p = Path(value)
        if not p.is_file():
            raise argparse.ArgumentTypeError(
                f'{value!r} is not an existing file')
        return p

    def timeout_tuple(value: str) -> Tuple[float, ...]:
        # allow "1", "1,2", "1 2"
        parts = value.replace(',', ' ').split()

        if not (1 <= len(parts) <= 2):
            raise argparse.ArgumentTypeError('timeout must be 1 or 2 floats')

        try:
            vals = tuple(float(p) for p in parts)
        except ValueError:
            raise argparse.ArgumentTypeError(
                "timeout values must be floats"
            )
        return vals

    def ssl_verify(value: str) -> Union[bool, Path]:
        if value == 'yes':
            return True
        if value == 'no':
            return False
        p = Path(value)
        if not (p.is_file() or p.is_dir()):
            raise argparse.ArgumentTypeError(
                'verify must be yes, no or cafile, capath')
        return p

    def description(value: str) -> str:
        if not value.startswith('@'):
            return value

        filename = value[1:]
        if not filename:
            raise argparse.ArgumentTypeError("missing filename after '@'")

        path = Path(filename)

        try:
            return path.read_text(encoding='utf-8')
        except OSError as e:
            raise argparse.ArgumentTypeError(f'{path}: {e}') from e

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='update SCM trusted CAs',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-C', '--credentials',
                        required=True,
                        metavar='PATH',
                        type=existing_file,
                        help='OAuth2 JSON client credentials path')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--snippet',
                       metavar='NAME',
                       help='SCM snippet')
    group.add_argument('--folder',
                       metavar='NAME',
                       help='SCM folder')
    parser.add_argument('--certs',
                        metavar='PATH',
                        type=existing_file,
                        help='certificate archive path')
    parser.add_argument('--update',
                        action='store_true',
                        help='update certificates')
    parser.add_argument('--delete',
                        action='store_true',
                        help='delete all previously added certificates')
    parser.add_argument('-T', '--type',
                        action='append',
                        choices=['root', 'intermediate'],
                        help='certificate type(s) for update')
    parser.add_argument('--update-trusted',
                        action='store_true',
                        help='update trusted root CA for all certificates')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help="don't update SCM")
    parser.add_argument('--description',
                        nargs='?',
                        const=Description.NO_ARGUMENT,
                        default=Description.UNSPECIFIED,
                        type=description,
                        metavar="TEXT|@PATH",
                        help='update snippet description')
    parser.add_argument('--show',
                        action='store_true',
                        help='show %s managed config' % title)
    parser.add_argument('--show-tree',
                        action='store_true',
                        help='show %s managed certificates in tree format' %
                        title)
    parser.add_argument('--jwt',
                        action='store_true',
                        help='print JSON Web Token')
    parser.add_argument('--api-url',
                        metavar='URL',
                        help='''\
API URL
default %s''' % API_URL)
    parser.add_argument('--oauth2-url',
                        metavar='URL',
                        help='''\
OAuth2 URL
default %s''' % OAUTH2_URL)
    parser.add_argument('--timeout',
                        type=timeout_tuple,
                        metavar='T[,T]',
                        help='API timeout')
    parser.add_argument('--verify',
                        type=ssl_verify,
                        metavar='OPTION',
                        help='SSL server verify option: yes|no|cafile|capath')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='enable verbosity')
    parser.add_argument('--debug',
                        type=int,
                        choices=[0, 1, 2, 3],
                        default=0,
                        help='enable debug')
    parser.add_argument('--dtime',
                        action='store_true',
                        help='add time string to debug output')
    x = '%s %s' % (title, __version__)
    parser.add_argument('--version',
                        action='version',
                        help='display version',
                        version=x)
    args = parser.parse_args()

    if args.debug:
        print(args, file=sys.stderr)

    return args


if __name__ == '__main__':
    main()
