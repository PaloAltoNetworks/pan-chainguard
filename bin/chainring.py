#!/usr/bin/env python3

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

import argparse
import asyncio
from html import escape
import json
import os
import sys
from treelib import Tree

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
import pan_chainguard.util

args = None


def format_text(tree):
    txt = tree.show(stdout=None)
    print(txt, end='')


def format_rst(tree):
    def tree_to_rst(tree, node_id=None, level=0):
        if node_id is None:
            node_id = tree.root

        node = tree[node_id]
        lines = [f'{"  " * level}* {node.tag}']

        for i, child in enumerate(tree.children(node_id)):
            if i == 0:
                lines.append('')
            lines.extend(tree_to_rst(tree, child.identifier, level + 1))

        return lines

    lines = tree_to_rst(tree)
    rst = ''
    if args.title:
        rst = f'{args.title}\n{"=" * len(args.title)}\n'
    rst += '\n'.join(lines)
    print(rst)


def format_html(tree):
    def tree_to_html(tree, node_id=None):
        if node_id is None:
            node_id = tree.root

        node = tree[node_id]
        children = tree.children(node_id)

        sha256 = str(node_id)
        if len(sha256) == 64:
            html = (f'<li><a href="https://crt.sh/?q={sha256}">'
                    f'<code>{sha256}</code></a>'
                    f'{escape(node.tag[64:])}\n')
        else:
            html = f'<li>{escape(node.tag)}\n'

        if children:
            html += '<ul>'
            for child in children:
                html += tree_to_html(tree, child.identifier)
            html += '</ul>\n'

        html += '</li>\n'

        return html

    html = ''
    if args.title:
        html += f'<h1>{escape(args.title)}</h1>\n'
    html += f'<ul>{tree_to_html(tree)}</ul>'
    print(html)


def format_json(tree):
    data = pan_chainguard.util.tree_to_dict(tree=tree)
    json_data = json.dumps(data, indent=4)
    print(json_data)


formats = {
    'txt': format_text,
    'rst': format_rst,
    'html': format_html,
    'json': format_json,
}


def main():
    global args
    args = parse_args()

    ret = asyncio.run(main_loop())

    sys.exit(ret)


async def main_loop():
    tree = read_tree()

    if args.test_collisions:
        if not test_collisions(tree):
            return 1

    if args.format:
        for format in args.format:
            formats[format](tree)

    return 0


def read_tree():
    try:
        with open(args.tree, 'r') as f:
            json_data = f.read()
        data = json.loads(json_data)
    except (OSError, TypeError) as e:
        print('%s: %s' % (args.tree, e), file=sys.stderr)
        sys.exit(1)

    try:
        tree = pan_chainguard.util.dict_to_tree(data=data)
    except pan_chainguard.util.UtilError as e:
        print('%s: %s' % (args.tree, e), file=sys.stderr)
        sys.exit(1)

    return tree


# The first 26 characters of the SHA-256 fingerprint (length 64) are
# used for the PAN-OS certificate name; test name for collisions.
def test_collisions(tree):
    data = pan_chainguard.util.tree_to_dict(tree=tree)

    names = []
    collisions = []

    for x in data['nodes']:
        if x['identifier']:
            name = pan_chainguard.util.hash_to_name(
                sha256=x['identifier'])
            if name in names:
                collisions.append(name)
                print('collision %s' % name, file=sys.stderr)
            else:
                names.append(name)

    if collisions:
        print('%d certificate name collisions: %s' %
              (len(collisions), collisions),
              file=sys.stderr)
        return False
    else:
        print('no certificate name collisions', file=sys.stderr)
        return True


def parse_args():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='certificate tree analysis and reporting')
    parser.add_argument('--tree',
                        required=True,
                        metavar='PATH',
                        help='JSON certificate tree path')
    parser.add_argument('-f', '--format',
                        action='append',
                        choices=formats.keys(),
                        help='output format')
    parser.add_argument('-t', '--title',
                        help='report title')
    parser.add_argument('--test-collisions',
                        action='store_true',
                        help='test for certificate name collisions')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='enable verbosity')
    parser.add_argument('--debug',
                        type=int,
                        choices=[0, 1, 2, 3],
                        default=0,
                        help='enable debug')
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
