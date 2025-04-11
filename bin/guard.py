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
from collections import defaultdict
import logging
import os
import pprint
import re
import sys
import time
from treelib import Node, Tree
import xml.etree.ElementTree as etree

try:
    import pan.xapi
except ImportError:
    print('Install pan-python: https://pypi.org/project/pan-python/',
          file=sys.stderr)
    sys.exit(1)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from pan_chainguard import (title, __version__)
import pan_chainguard.util

# XXX keep compatible with sequence based naming for now
NAME_RE = pan_chainguard.util.NAME_RE_COMPAT

args = None


class Xpath():
    def __init__(self, *,
                 panorama=False,
                 template=None,
                 vsys=None):
        self.type = 'panorama' if panorama else 'firewall'
        if self.type == 'firewall' and template is not None:
            raise ValueError('template set for firewall')
        self.template = template
        self.vsys = vsys

    def __str__(self):
        x = self.__dict__
        return ', '.join((': '.join((k, str(x[k]))))
                         for k in sorted(x))

    @property
    def panorama(self):
        return self.type == 'panorama'

    def _variant(self, xpath):
        if self.type == 'firewall':
            if self.vsys is None:
                x = xpath[self.type]['shared']
            else:
                x = xpath[self.type]['vsys'] % self.vsys
        elif self.type == 'panorama':
            if self.template is None:
                x = xpath[self.type]['panorama']
            elif self.vsys is None:
                x = xpath[self.type]['template']['shared'] % self.template
            else:
                x = xpath[self.type]['template']['vsys'] % (
                    self.template, self.vsys)
        else:
            assert False, 'Malformed type: %s' % self.type

        return x

    def trusted_root_ca(self):
        xpath = {
            'firewall': {
                'shared': '/config/shared/ssl-decrypt/trusted-root-CA',
                'vsys': ("/config/devices/entry"
                         "[@name='localhost.localdomain']"
                         "/vsys/entry[@name='%s']/ssl-decrypt"
                         "/trusted-root-CA")
            },

            'panorama': {
                'panorama': '/config/panorama/ssl-decrypt/trusted-root-CA',
                'template': {
                    'shared': ("/config/devices/entry"
                               "[@name='localhost.localdomain']"
                               "/template/entry[@name='%s']/config/shared"
                               "/ssl-decrypt/trusted-root-CA"),
                    'vsys': ("/config/devices/entry"
                             "[@name='localhost.localdomain']"
                             "/template/entry[@name='%s']/config/devices"
                             "/entry[@name='localhost.localdomain']/vsys"
                             "/entry[@name='%s']/ssl-decrypt/trusted-root-CA")
                },
            },
        }

        return self._variant(xpath)

    def certificates(self):
        xpath = {
            'firewall': {
                'shared': '/config/shared/certificate',
                'vsys': ("/config/devices/entry[@name='localhost.localdomain']"
                         "/vsys/entry[@name='%s']/certificate"),
            },

            'panorama': {
                'panorama': '/config/panorama/certificate',
                'template': {
                    'shared': ("/config/devices/entry"
                               "[@name='localhost.localdomain']"
                               "/template/entry[@name='%s']"
                               "/config/shared/certificate"),
                    'vsys': ("/config/devices/entry"
                             "[@name='localhost.localdomain']"
                             "/template/entry[@name='%s']/config/devices"
                             "/entry[@name='localhost.localdomain']"
                             "/vsys/entry[@name='%s']/certificate")
                },
            },
        }

        return self._variant(xpath)

    def root_ca_exclude_list(self):
        xpath = {
            'firewall': {
                'shared': '/config/shared/ssl-decrypt/root-ca-exclude-list',
                'vsys': ("/config/devices/entry[@name='localhost.localdomain']"
                         "/vsys/entry[@name='%s']/ssl-decrypt/"
                         "root-ca-exclude-list"),
            },

            'panorama': {
                'panorama': ('/config/panorama/ssl-decrypt/'
                             'root-ca-exclude-list'),
                'template': {
                    'shared': ("/config/devices/entry"
                               "[@name='localhost.localdomain']"
                               "/template/entry[@name='%s']"
                               "/config/shared/ssl-decrypt/"
                               "root-ca-exclude-list"),
                    'vsys': ("/config/devices/entry"
                             "[@name='localhost.localdomain']"
                             "/template/entry[@name='%s']/config/devices"
                             "/entry[@name='localhost.localdomain']"
                             "/vsys/entry[@name='%s']/ssl-decrypt/"
                             "root-ca-exclude-list")
                },
            },
        }

        return self._variant(xpath)


def main():
    global args
    args = parse_args()

    logger = logging.getLogger(pan.xapi.__name__)
    if args.xdebug == 3:
        logger.setLevel(pan.xapi.DEBUG3)
    elif args.xdebug == 2:
        logger.setLevel(pan.xapi.DEBUG2)
    elif args.xdebug == 1:
        logger.setLevel(pan.xapi.DEBUG1)

    log_format = '%(name)s: %(message)s'
    handler = logging.StreamHandler()
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    asyncio.run(main_loop())

    sys.exit(0)


async def main_loop():
    xapi = None
    panorama = False

    try:
        xapi = pan.xapi.PanXapi(tag=args.tag,
                                debug=args.xdebug)
        xapi.ad_hoc(modify_qs=True,
                    qs={'type': 'version'})
        elem = xapi.element_root.find('./result/model')
        if elem is not None:
            if elem.text == 'Panorama':
                panorama = True
        else:
            print("Can't get model", file=sys.stderr)
    except pan.xapi.PanXapiError as e:
        print('pan.xapi.PanXapi:', e, file=sys.stderr)
        sys.exit(1)

    xpath = Xpath(panorama=panorama,
                  vsys=args.vsys,
                  template=args.template)
    if args.debug > 1:
        print('Xpath():', str(xpath), file=sys.stderr)
        print(xpath.certificates(), file=sys.stderr)
        print(xpath.trusted_root_ca(), file=sys.stderr)
        print(xpath.root_ca_exclude_list(), file=sys.stderr)

    if args.show:
        show(xapi, xpath)
    if args.show_tree:
        show_tree(xapi, xpath)

    # experimental
    if args.enable_trusted:
        enable_trusted(xapi, xpath)

    # experimental
    if args.disable_trusted:
        disable_trusted(xapi, xpath)

    if args.update_trusted:
        update_trusted_root_cas(xapi, xpath, quiet=False)

    if args.delete:
        delete_certs(xapi, xpath)

    if args.update:
        if args.certs is None:
            print('--certs argument required', file=sys.stderr)
            sys.exit(1)
        if args.type is None:
            print('--type argument required', file=sys.stderr)
            sys.exit(1)

        update_certs(xapi, xpath)

    if args.commit:
        commit(xapi, panorama)


def exclude_cert(sha256):
    EXCLUDE = [
        # This root is in microsoft root store and is PAN-OS predefined
        # 0216_CCA_India_2015_SPL.
        # Expires Jan 29 11:36:43 2025 GMT.
        # 'openssl verify -check_ss_sig' fails with bad signature
        # PAN-257401
        'C34C5DF53080078FFE45B21A7F600469917204F4F0293F1D7209393E5265C04F',
        # XXX Signature Algorithm: rsassaPss
        '233525D6E906A9B99176204E3C2B4FBF5CEE03F2D126B2E64428BDF97CBC6138',
    ]

    if sha256 in EXCLUDE:
        if args.debug:
            print('Skip problem certificate %s' % sha256, file=sys.stderr)
        return True

    return False


def enable_trusted(xapi, xpath):
    kwargs = {'xpath': xpath.root_ca_exclude_list()}
    api_request(xapi, xapi.get, kwargs, 'success', ['7', '19'])
    disabled = xapi.element_root.findall(
        './result/root-ca-exclude-list/member')

    if args.dry_run:
        kwargs2 = {'xpath': '/config/predefined/trusted-root-ca'}
        api_request(xapi, xapi.get, kwargs2, 'success', '19')
        total = xapi.element_root.findall(
            './result/trusted-root-ca/entry')

        print('enable-trusted dry-run: %d default trusted root CAs,'
              ' %d are disabled, %d to enable' % (
                  len(total), len(disabled), len(disabled)))
        return

    if len(disabled):
        api_request(xapi, xapi.delete, kwargs, 'success', '20')

    print('%d default trusted root CAs enabled' % len(disabled))


def disable_trusted(xapi, xpath):
    kwargs = {'xpath': '/config/predefined/trusted-root-ca'}
    api_request(xapi, xapi.get, kwargs, 'success', '19')
    entries = xapi.element_root.findall('./result/trusted-root-ca/entry')

    kwargs = {'xpath': xpath.root_ca_exclude_list()}
    api_request(xapi, xapi.get, kwargs, 'success', ['7', '19'])
    disabled = xapi.element_root.findall(
        './result/root-ca-exclude-list/member')

    if args.dry_run:
        enabled = len(entries) - len(disabled)
        print('disable-trusted dry-run: %d default trusted root CAs,'
              ' %d are enabled, %d to disable' % (
                  len(entries), enabled, enabled))
        return

    disabled_ = []
    for entry in disabled:
        name = entry.text
        disabled_.append(name)

    members = []
    for entry in entries:
        name = entry.attrib['name']
        if name in disabled_:
            continue
        member = '<member>%s</member>' % name
        members.append(member)

        if args.verbose:
            print('disabling', name, file=sys.stderr)

    if members:
        root_ca_exclude = xpath.root_ca_exclude_list()
        element = ''.join(members)

        kwargs = {
            'xpath': root_ca_exclude,
            'element': element,
        }
        api_request(xapi, xapi.set, kwargs, 'success', '20')

    print('%d default trusted root CAs disabled' % len(members))


def get_certs(xapi, xpath):
    certificates = xpath.certificates()
    kwargs = {'xpath': certificates}
    api_request(xapi, xapi.get, kwargs, 'success', ['7', '19'])
    if xapi.status_code == '7':
        return []

    entries = xapi.element_root.findall('./result/certificate/entry')

    data = {}
    prog = re.compile(NAME_RE)
    progcn = re.compile(r'/CN=([^/]+)')

    for entry in entries:
        name = entry.attrib['name']
        if prog.search(name):
            subject = entry.find('./subject').text
            subject_cn = None
            match = progcn.search(subject)
            if match:
                subject_cn = match.group(1)
            issuer = entry.find('./issuer').text
            issuer_cn = None
            match = progcn.search(issuer)
            if match:
                issuer_cn = match.group(1)
            expiry = entry.find('./expiry-epoch').text
            try:
                if time.time() > int(expiry):
                    expired = True
                else:
                    expired = False
            except ValueError as e:
                print('%s expiry-epoch %s: %s' % (
                    name, expiry, e), file=sys.stderr)

            v = {
                'cert-name': name,
                'subject': subject,
                'subject-cn': subject_cn,
                'subject-hash': entry.find('./subject-hash').text,
                'issuer': issuer,
                'issuer-cn': issuer_cn,
                'issuer-hash': entry.find('./issuer-hash').text,
                'expired': expired,
            }
            data[name] = v

    return data


def delete_certs(xapi, xpath):
    data = get_certs(xapi, xpath)

    if args.dry_run:
        print('delete dry-run: %d to delete' % len(data))
        return

    for name in data:
        delete_cert(xapi, xpath, name)

    print('%d certificates deleted' % len(data))


def delete_cert(xapi, xpath, name):
    rootca = xpath.trusted_root_ca()
    member = "/member[text()='%s']" % name
    kwargs = {'xpath': rootca + member}
    api_request(xapi, xapi.delete, kwargs, 'success', ['7', '20'])

    certificates = xpath.certificates()
    entry = "/entry[@name='%s']" % name
    kwargs = {'xpath': certificates + entry}
    # XXX can return status_code 7 intermittently; workaround is
    # to re-run
    api_request(xapi, xapi.delete, kwargs, 'success', '20')
    if args.verbose:
        print('deleted', name, file=sys.stderr)


def get_trusted_root_cas(xapi, xpath):
    trusted_root_ca = xpath.trusted_root_ca()
    kwargs = {'xpath': trusted_root_ca}
    api_request(xapi, xapi.get, kwargs, 'success', ['7', '19'])

    prog = re.compile(NAME_RE)
    data = []
    if xapi.status_code == '19':
        entries = xapi.element_root.findall(
            './result/trusted-root-CA/member')
        for entry in entries:
            name = entry.text
            if prog.search(name):
                data.append(name)

    return data


def update_trusted_root_cas(xapi, xpath, quiet=True):
    cert_names = get_certs(xapi, xpath)
    add = []

    if cert_names:
        data = get_trusted_root_cas(xapi, xpath)
        if data:
            for name in cert_names:
                if name not in data:
                    add.append(name)
        else:
            add.extend(cert_names)

    if args.dry_run:
        print('update-trusted dry-run: %d certificates'
              ' to enable as trusted root CAs' % len(add))
        return

    if add:
        add_trusted_root_cas(xapi, xpath, add)

    if not quiet:
        print('%d certificates enabled as trusted root CA' % len(add))


def add_trusted_root_cas(xapi, xpath, cert_names):
    members = []

    for x in cert_names:
        members.append('<member>%s</member>' % x)

    trusted_root_ca = xpath.trusted_root_ca()
    element = ''.join(members)

    kwargs = {
        'xpath': trusted_root_ca,
        'element': element,
    }

    api_request(xapi, xapi.set, kwargs, 'success', '20')


def update_certs(xapi, xpath):
    old = get_certs(xapi, xpath)

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
        cert_name = pan_chainguard.util.hash_to_name(sha256=sha256)
        new[cert_name] = content

    old_set = set(old)
    new_set = set(new.keys())

    if args.debug > 2:
        print('old', pprint.pformat(old_set), file=sys.stderr)
        print('new', pprint.pformat(new_set), file=sys.stderr)

    delete = list(old_set - new_set)
    add = list(new_set - old_set)

    if args.debug > 1:
        print('update delete', pprint.pformat(delete), file=sys.stderr)
        print('update add', pprint.pformat(add), file=sys.stderr)

    if args.dry_run:
        print('update dry-run: %d to delete, %d to add' % (
            len(delete), len(add)))
        return

    for name in delete:
        delete_cert(xapi, xpath, name)
    print('%d certificates deleted' % len(delete))

    total = 0
    for name in add:
        if add_cert(xapi, xpath, name, new[name]):
            total += 1

    if total:
        add_trusted_root_cas(xapi, xpath, add_cert.cert_names)

    print('%d certificates added' % total)


def add_cert(xapi, xpath, cert_name, content):
    kwargs = {
        'category': 'certificate',
        'file': content,
        'extra_qs': {
            'certificate-name': cert_name,
            'format': 'pem',
        },
    }

    if xpath.panorama:
        if args.template is not None:
            kwargs['extra_qs']['target-tpl'] = args.template
        if args.vsys is not None:
            # XXX does not work; PAN-257229
            kwargs['extra_qs']['target-tpl-vsys'] = args.vsys
    elif args.vsys is not None:
        kwargs['vsys'] = args.vsys

    try:
        xapi.import_file(**kwargs)
    except pan.xapi.PanXapiError as e:
        if 'Certificate is expired' in str(e):
            if args.verbose:
                print('certificate is expired %s' % cert_name, file=sys.stderr)
            return False
        else:
            print('%s: %s: %s' % (xapi.import_file.__name__, kwargs, e),
                  file=sys.stderr)
            sys.exit(1)

    # Use function attribute to cache certificate names so we can use
    # a single API request to enable them as trusted root CAs.
    try:
        add_cert.cert_names.append(cert_name)
    except AttributeError:
        add_cert.cert_names = [cert_name]

    if args.verbose:
        print('added %s' % cert_name, file=sys.stderr)

    return True


def show(xapi, xpath):
    data = get_certs(xapi, xpath)
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
    print('%d Device Certificates%s' % (len(out), expired))
    if out and args.verbose:
        print('\n'.join(out))

    if out:
        data = get_trusted_root_cas(xapi, xpath)
        num = len(data)
        print('%d Trusted Root CA Certificates' % num)
        if num < len(out):
            print('Warning: %d certificates not trusted; '
                  'run guard.py --update-trusted' % (len(out) - num))


def show_tree(xapi, xpath):
    data = get_certs(xapi, xpath)
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

        node = Node(tag=tag, identifier=x['cert-name'])

        return node

    def add_children(parent, issuer):
        if issuer in issuers:
            for x in issuers[issuer]:
                if (tree.contains(x['cert-name']) or
                   x['subject-hash'] == x['issuer-hash']):
                    continue

                tree.add_node(build_node(x), parent=parent)
                add_children(x['cert-name'], x['subject-hash'])

    for x in roots + orphans:
        tree.add_node(build_node(x), parent=0)
        add_children(x['cert-name'], x['subject-hash'])

    print(tree.show(stdout=False), end='')

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


def commit(xapi, panorama):
    root = etree.Element('commit')
    partial = etree.SubElement(root, 'partial')
    desc = etree.SubElement(partial, 'description')
    desc.text = '%s %s' % (title, __version__)
    if args.admin:
        admin = etree.SubElement(partial, 'admin')
        admin_member = etree.SubElement(admin, 'member')
        admin_member.text = args.admin

    policy_and_objects = etree.Element('policy-and-objects')
    policy_and_objects.text = 'excluded'
    device_and_network = etree.Element('device-and-network')
    device_and_network.text = 'excluded'
    shared_object = etree.Element('shared-object')
    shared_object.text = 'excluded'

    if panorama:
        if args.template:
            # commit scope: template
            # no template vsys scope
            template = etree.SubElement(partial, 'template')
            template_member = etree.SubElement(template, 'member')
            template_member.text = args.template
        else:
            # commit scope: device-and-network
            partial.append(shared_object)
    else:
        # firewall
        if args.vsys:
            # commit scope: vsys
            vsys = etree.SubElement(partial, 'vsys')
            vsys_member = etree.SubElement(vsys, 'member')
            vsys_member.text = args.vsys
            partial.append(device_and_network)
            partial.append(shared_object)
        else:
            # commit scope: shared-object
            partial.append(device_and_network)
            partial.append(policy_and_objects)

    cmd = etree.tostring(root).decode()
    if args.debug:
        print(cmd, file=sys.stderr)

    kwargs = {
        'cmd': cmd,
        'sync': True,
    }

    if args.dry_run:
        return

    if args.verbose:
        print('commit config for admin %s' % args.admin)

    api_request(xapi, xapi.commit, kwargs, 'success')
    if args.debug:
        print(xapi.xml_root(), file=sys.stderr)

    if xapi.status_code is not None:
        code = ' [code=\"%s\"]' % xapi.status_code
    else:
        code = ''
    if xapi.status is not None:
        print('commit: %s%s' % (xapi.status, code), end='')
    if args.verbose and xapi.status_detail is not None:
        print(': "%s"' % xapi.status_detail.rstrip(), end='')
    print()


def api_request(xapi, func, kwargs, status=None, status_code=None):
    try:
        func(**kwargs)
    except pan.xapi.PanXapiError as e:
        print('%s: %s: %s' % (func.__name__, kwargs, e),
              file=sys.stderr)
        sys.exit(1)

    status_detail = (' "%s"' % xapi.status_detail
                     if xapi.status_detail is not None
                     else '')
    if (status is not None and
       not pan_chainguard.util.s1_in_s2(xapi.status, status)):
        print('%s: %s:%s status %s != %s' %
              (func.__name__, kwargs, xapi.status_detail,
               xapi.status, status),
              file=sys.stderr)
        sys.exit(1)

    if (status_code is not None and
       not pan_chainguard.util.s1_in_s2(xapi.status_code, status_code)):
        print('%s: %s:%s status_code %s != %s' %
              (func.__name__, kwargs, status_detail,
               xapi.status_code, status_code),
              file=sys.stderr)
        sys.exit(1)


def parse_args():
    def check_vsys(x):
        if x.isdigit():
            x = 'vsys' + x
        return x

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='update PAN-OS trusted CAs')
    parser.add_argument('--tag', '-t',
                        required=True,
                        help='.panrc tagname')
    parser.add_argument('--vsys',
                        type=check_vsys,
                        help='vsys name or number')
    parser.add_argument('--template',
                        help='Panorama template')
    parser.add_argument('--certs',
                        metavar='PATH',
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
    # XXX experimental
    # We don't want to have a condition where default trusted CAs
    # are disabled but there are no replacement root CAs.  Better
    # to just keep default trusted CAs enabled.
    parser.add_argument('--disable-trusted',
                        action='store_true',
                        help=argparse.SUPPRESS)
#                        help='disable all default trusted root CAs')
    parser.add_argument('--enable-trusted',
                        action='store_true',
                        help=argparse.SUPPRESS)
#                        help='enable all default trusted root CAs')
    parser.add_argument('--update-trusted',
                        action='store_true',
                        help='update trusted root CA for all certificates')
    parser.add_argument('--commit',
                        action='store_true',
                        help='commit configuration')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help="don't update PAN-OS")
    parser.add_argument('--show',
                        action='store_true',
                        help='show %s managed config' % title)
    parser.add_argument('--show-tree',
                        action='store_true',
                        help='show %s managed certificates in tree format' %
                        title)
    parser.add_argument('--admin',
                        help='commit admin')
    parser.add_argument('--xdebug',
                        type=int,
                        choices=[0, 1, 2, 3],
                        default=0,
                        help='pan.xapi debug')
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
