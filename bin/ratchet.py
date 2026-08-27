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
from datetime import datetime, timezone
import hashlib
from html import escape
import json
import os
import sys


libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import title, __version__
import pan_chainguard.util


ROOT_HISTORY_VERSION = 0


def main():
    args = parse_args()

    try:
        if args.tree:
            date = args.date
            if date is None:
                date = datetime.now(timezone.utc).date().isoformat()

        history = root_history_load(args.history)
        if history is None:
            if not args.tree:
                print('%s: root history does not exist' % args.history,
                      file=sys.stderr)
                return 1

            tree = read_tree(args.tree)

            history = root_history_new(tree, date)
            root_history_save(args.history, history)
            if args.verbose:
                print('%s: root history state initialized %s'
                      % (args.history, date), file=sys.stderr)

        elif args.previous_tree:
            tree = read_tree(args.tree)
            previous_tree = read_tree(args.previous_tree)
            if root_history_update(history, previous_tree, tree, date):
                root_history_save(args.history, history)
                if args.verbose:
                    print('%s: root history state updated %s'
                          % (args.history, date), file=sys.stderr)
            elif args.verbose:
                print('%s: root history state unchanged %s'
                      % (args.history, date), file=sys.stderr)

        if args.format:
            formats[args.format](history, args.title)

    except ValueError as e:
        print(e, file=sys.stderr)
        return 1

    return 0


def read_tree(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError('%s: %s' % (path, e)) from e

    try:
        return pan_chainguard.util.dict_to_tree(data=data)
    except pan_chainguard.util.UtilError as e:
        raise ValueError('%s: %s' % (path, e)) from e


CERT_ITEM_FIELDS = {
    'subject': 'Certificate Name',
    'ca_owner': 'Parent Certificate Name',
}


def certificate_item(node):
    item = {
        'sha256': node.identifier,
    }

    for name, key in CERT_ITEM_FIELDS.items():
        value = node.data.get(key)
        if value:
            item[name] = value

    return item


def root_certificates(tree):
    roots = {}

    for node in tree.all_nodes():
        data = node.data
        if (isinstance(data, dict) and
                data.get('Certificate Record Type') == 'Root Certificate'):
            sha256 = node.identifier
            if not isinstance(sha256, str):
                raise ValueError('root certificate identifier is not a string')
            roots[sha256] = certificate_item(node)

    return roots


def root_set_sha256(roots):
    data = '\n'.join(sorted(roots)).encode('ascii')
    return hashlib.sha256(data).hexdigest()


def root_history_validate(history):
    if not isinstance(history, dict):
        raise ValueError('root history is not an object')

    version = history.get('version')
    if version != ROOT_HISTORY_VERSION:
        raise ValueError('unsupported root history version: %r' % version)

    events = history.get('events')
    if not isinstance(events, list):
        raise ValueError('root history events is not a list')
    if not events:
        raise ValueError('root history events is empty')

    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError('root history event %d is not an object' %
                             (idx + 1))

        date = event.get('date')
        if not isinstance(date, str):
            raise ValueError('root history event %d date is not a string' %
                             (idx + 1))
        try:
            d = datetime.strptime(date, '%Y-%m-%d')
            if d.strftime('%Y-%m-%d') != date:
                raise ValueError()
        except ValueError as e:
            raise ValueError(
                'invalid root history event %d date: %r' %
                (idx + 1, date)) from e

        roots = event.get('roots')
        if (not isinstance(roots, int) or isinstance(roots, bool) or
                roots < 0):
            raise ValueError(
                'root history event %d roots is not an integer >= 0' %
                (idx + 1))

        root_set_sha256_ = event.get('root_set_sha256')
        if not isinstance(root_set_sha256_, str):
            raise ValueError(
                'root history event %d root_set_sha256 is not a string' %
                (idx + 1))

        for name in ('added', 'deleted'):
            items = event.get(name)
            if not isinstance(items, list):
                raise ValueError(
                    'root history event %d %s is not a list' %
                    (idx + 1, name))
            for item_idx, item in enumerate(items):
                if not isinstance(item, dict):
                    raise ValueError(
                        'root history event %d %s item %d is not an object' %
                        (idx + 1, name, item_idx + 1))
                sha256 = item.get('sha256')
                if not isinstance(sha256, str):
                    raise ValueError(
                        'root history event %d %s item %d'
                        ' sha256 is not a string' %
                        (idx + 1, name, item_idx + 1))
                for field in CERT_ITEM_FIELDS:
                    value = item.get(field)
                    if value is not None and not isinstance(value, str):
                        raise ValueError(
                            'root history event %d %s item %d'
                            ' %s is not a string' %
                            (idx + 1, name, item_idx + 1, field))

        description = event.get('description')
        if not isinstance(description, str):
            raise ValueError(
                'root history event %d description is not a string' %
                (idx + 1))


def root_history_load(path):
    if not os.path.exists(path):
        return None

    try:
        with open(path, 'r') as f:
            history = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError('%s: %s' % (path, e)) from e

    try:
        root_history_validate(history)
    except ValueError as e:
        raise ValueError('%s: %s' % (path, e)) from e

    return history


def root_history_save(path, history):
    try:
        with open(path, 'w') as f:
            json.dump(history, f, separators=(',', ':'))
            f.write('\n')
    except OSError as e:
        raise ValueError('%s: %s' % (path, e)) from e


def root_history_new(tree, date):
    roots = root_certificates(tree)

    event = {
        'date': date,
        'roots': len(roots),
        'root_set_sha256': root_set_sha256(roots),
        'added': [],
        'deleted': [],
        'description': 'initial root store',
    }

    return {
        'version': ROOT_HISTORY_VERSION,
        'events': [event],
    }


def root_history_current_event(history):
    return history['events'][-1]


def root_history_update(history, previous_tree, tree, date):
    previous_roots = root_certificates(previous_tree)
    current_roots = root_certificates(tree)

    previous_sha256 = root_set_sha256(previous_roots)
    current_sha256 = root_set_sha256(current_roots)
    current_event = root_history_current_event(history)
    expected_sha256 = current_event['root_set_sha256']

    # A workflow retry can present the same resulting tree after the event
    # has already been written to the history file.
    if current_sha256 == expected_sha256:
        return False

    expected = current_event['roots']
    if len(previous_roots) != expected:
        raise ValueError(
            'root history previous root count is %d, previous tree contains '
            '%d roots' % (expected, len(previous_roots)))

    if previous_sha256 != expected_sha256:
        raise ValueError(
            'previous tree does not match current root history state')

    added = current_roots.keys() - previous_roots.keys()
    deleted = previous_roots.keys() - current_roots.keys()

    event = {
        'date': date,
        'roots': len(current_roots),
        'root_set_sha256': current_sha256,
        'added': [current_roots[x] for x in sorted(added)],
        'deleted': [previous_roots[x] for x in sorted(deleted)],
        'description': 'root store update',
    }

    history['events'].append(event)
    return True


def format_json(history, title=None):
    print(json.dumps(history, indent=4))


def format_txt(history, title=None):
    events = history['events']

    if title:
        print(title)
        print()

    print('%-10s %5s %9s %9s %5s  %s' % (
        'Date', 'Roots', 'Additions', 'Deletions', 'Net', 'Description'))

    for event in reversed(events):
        initial = event is events[0]

        if initial:
            additions = '-'
            deletions = '-'
            net = '-'
        else:
            additions = str(len(event['added']))
            deletions = str(len(event['deleted']))
            net = '%+d' % (len(event['added']) - len(event['deleted']))

        print('%-10s %5d %9s %9s %5s  %s' % (
            event['date'],
            event['roots'],
            additions,
            deletions,
            net,
            event['description']))


def format_html(history, title=None):
    events = history['events']

    rows = ''
    for event in reversed(events):
        initial = event is events[0]
        if initial:
            additions = '&mdash;'
            deletions = '&mdash;'
            net = '&mdash;'
        else:
            additions = str(len(event['added']))
            deletions = str(len(event['deleted']))
            net = '%+d' % (len(event['added']) - len(event['deleted']))

        rows += f'''<tr>
<td>{escape(event['date'])}</td>
<td class="number">{event['roots']}</td>
<td class="number">{additions}</td>
<td class="number">{deletions}</td>
<td class="number">{net}</td>
<td>{escape(event['description'])}</td>
</tr>
'''

    details = ''
    for event in reversed(events[1:]):
        additions = len(event['added'])
        deletions = len(event['deleted'])
        addition_text = 'addition' if additions == 1 else 'additions'
        deletion_text = 'deletion' if deletions == 1 else 'deletions'
        details += (
            '<details>\n'
            f'<summary>{escape(event["date"])}: '
            f'{additions} {addition_text}, '
            f'{deletions} {deletion_text}</summary>\n')

        if event['description'] != 'root store update':
            details += f'<p>{escape(event["description"])}</p>\n'

        if event['added']:
            details += '<h3>Added</h3>\n<ul>\n'
            for item in sorted(
                    event['added'],
                    key=lambda x: (x.get('subject', '').casefold(),
                                   x['sha256'])):
                sha256_ = escape(item['sha256'])
                details += (
                    f'<li><a href="https://crt.sh/?sha256={sha256_}">'
                    f'<code>{sha256_}</code></a>')
                if item.get('subject'):
                    details += f' Subject: "{escape(item["subject"])}"'
                if item.get('ca_owner'):
                    details += f' CA-Owner: "{escape(item["ca_owner"])}"'
                details += '</li>\n'
            details += '</ul>\n'

        if event['deleted']:
            details += '<h3>Deleted</h3>\n<ul>\n'
            for item in sorted(
                    event['deleted'],
                    key=lambda x: (x.get('subject', '').casefold(),
                                   x['sha256'])):
                sha256_ = escape(item['sha256'])
                details += (
                    f'<li><a href="https://crt.sh/?sha256={sha256_}">'
                    f'<code>{sha256_}</code></a>')
                if item.get('subject'):
                    details += f' Subject: "{escape(item["subject"])}"'
                if item.get('ca_owner'):
                    details += f' CA-Owner: "{escape(item["ca_owner"])}"'
                details += '</li>\n'
            details += '</ul>\n'

        details += '</details>\n'

    html_title = ''
    heading = ''
    if title:
        title_ = escape(title)
        html_title = f'<title>{title_}</title>\n'
        heading = f'<h1>{title_}</h1>\n'

    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

    footer = f'''<footer>
<p><em>Generated: {date_str}</em></p>
</footer>
'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
{html_title}<style>
body {{
    font-family: sans-serif;
    margin: 2em;
}}
table {{
    border-collapse: collapse;
    margin: 1em 0 2em 0;
}}
th, td {{
    border: 1px solid #bbb;
    padding: 0.4em 0.7em;
}}
th {{
    background: #eee;
    text-align: left;
}}
.number {{
    text-align: right;
}}
details {{
    margin: 0.75em 0;
}}
</style>
</head>
<body>
{heading}<table>
<table>
<thead>
<tr>
<th>Date</th>
<th>Roots</th>
<th>Additions</th>
<th>Deletions</th>
<th>Net</th>
<th>Description</th>
</tr>
</thead>
<tbody>
{rows}</tbody>
</table>
{details}{footer}</body>
</html>
'''

    print(html, end='')


formats = {
    'txt': format_txt,
    'json': format_json,
    'html': format_html,
}


def parse_args():
    def iso_date(s):
        try:
            d = datetime.strptime(s, '%Y-%m-%d')
            if d.strftime('%Y-%m-%d') != s:
                raise ValueError()
        except ValueError:
            raise argparse.ArgumentTypeError(
                'must be a date in YYYY-MM-DD format')

        return s

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='root store history management and reporting')
    parser.add_argument('--tree',
                        metavar='PATH',
                        help='current JSON certificate tree path')
    parser.add_argument('--previous-tree',
                        metavar='PATH',
                        help='previous JSON certificate tree path')
    parser.add_argument('--history',
                        required=True,
                        metavar='PATH',
                        help='JSON root history state path')
    parser.add_argument('--date',
                        type=iso_date,
                        metavar='YYYY-MM-DD',
                        help='root history date (default: current UTC date)')
    parser.add_argument('-f', '--format',
                        choices=formats.keys(),
                        help='root history output format')
    parser.add_argument('-t', '--title',
                        help='report title')
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

    if args.previous_tree and not args.tree:
        parser.error('--previous-tree requires --tree')
    if args.date and not args.tree:
        parser.error('--date requires --tree')

    return args


if __name__ == '__main__':
    sys.exit(main())
