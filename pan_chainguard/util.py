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

import csv
import io
import os
import re
import tarfile
import time
import treelib
from typing import Union

NAME_PREFIX = 'LINK-'
NAME_RE = r'^%s%s$' % (NAME_PREFIX, '[A-F0-9]{26,26}')
NAME_RE_COMPAT = r'^(\d{4,4}|LINK)-[0-9A-F]{26,26}$'


class UtilError(Exception):
    pass


def s1_in_s2(s1: str, s2: Union[str, list[str]]) -> bool:
    if isinstance(s2, str):
        return s1 == s2
    elif isinstance(s2, list):
        return s1 in s2
    else:
        raise ValueError('Invalid type for s2. '
                         'Must be a string or a list of strings.')


def is_writable(path: str) -> bool:
    # Check if the file exists
    if os.path.exists(path):
        # If the file exists, check if it is writable
        return os.access(path, os.W_OK)
    else:
        # If the file doesn't exist, check if the directory is writable
        parent_dir = os.path.dirname(path) or '.'
        return os.access(parent_dir, os.W_OK)


def read_cert_archive(*, path: str) -> dict[str, tuple[str, str]]:
    def parse_name(name):
        pat = (r'^(intermediate|root)/'
               r'[0-9A-F]{64,64}\.pem$')
        if not re.search(pat, name):
            e = 'malformed path in archive: %s' % name
            raise UtilError(e)
        type_, pem = os.path.split(name)
        sha256 = pem[:64]

        return type_, sha256

    data = {}
    try:
        with tarfile.open(name=path, mode='r') as tar:
            for member in tar:
                cert_type, sha256 = parse_name(member.name)
                f = tar.extractfile(member)
                content = f.read()
                data[sha256] = (cert_type, content)

    except (tarfile.TarError, OSError) as e:
        raise UtilError(str(e))

    return data


def write_cert_archive(*, path: str, data: dict[str, tuple[str, str]]):
    try:
        with tarfile.open(name=path, mode='w:gz') as tar:
            for k, v in data.items():
                name = os.path.join(v[0], k + '.pem')
                member = tarfile.TarInfo(name=name)
                member.size = len(v[1])
                member.mtime = time.time()
                content = (v[1].encode() if isinstance(v[1], str)
                           else v[1])
                f = io.BytesIO(content)
                tar.addfile(member, fileobj=f)
    except (tarfile.TarError, OSError) as e:
        raise UtilError(str(e))


def hash_to_name(*, sha256: str) -> str:
    # PAN-OS certificate-name max len 63
    # Panorama certificate-name max len 31
    # PAN-99186 won't do
    x = NAME_PREFIX + sha256
    return x[0:31]


def read_fingerprints(*, path: str) -> list[dict[str, str]]:
    try:
        with open(path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile,
                                    dialect='unix')
            x = []
            for row in reader:
                x.append(row)
    except OSError as e:
        raise UtilError(str(e))

    return x


def write_fingerprints(*, path: str, data: list[dict[str, str]]):
    fieldnames = [
        'type',
        'sha256',
    ]

    try:
        with open(path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile,
                                    dialect='unix',
                                    fieldnames=fieldnames)
            writer.writeheader()
            for x in data:
                row = {
                    'type': x['type'],
                    'sha256': x['sha256'],
                }
                writer.writerow(row)

    except OSError as e:
        raise UtilError(str(e))


def tree_to_dict(*, tree: treelib.Tree) -> dict:
    nodes = []

    for node in tree.all_nodes():
        parent = tree.parent(node.identifier)
        parent = parent if parent is None else parent.identifier
        x = {
            'identifier': node.identifier,
            'tag': node.tag,
            'data': node.data,
            'parent': parent,
        }
        nodes.append(x)

    return {'nodes': nodes}


def dict_to_tree(*, data: dict) -> treelib.Tree:
    root = {
        'identifier': 0,
        'tag': 'Root',
        'parent': None,
        'data': None,
    }

    if ('nodes' not in data or
       data['nodes'][0] != root):
        raise UtilError('Malformed tree dict')

    tree = treelib.Tree()

    for x in data['nodes']:
        tree.create_node(
            identifier=x['identifier'],
            tag=x['tag'],
            parent=x['parent'],
            data=x['data'])

    return tree
