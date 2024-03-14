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
import logging
import os
import re
import sys
import tarfile
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

args = None
panorama = False


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

    if args.tag:
        try:
            xapi = pan.xapi.PanXapi(tag=args.tag,
                                    debug=args.xdebug)
            xapi.ad_hoc(modify_qs=True,
                        qs={'type': 'version'})
            elem = xapi.element_root.find('./result/model')
            if elem is not None:
                if elem.text == 'Panorama':
                    global panorama
                    panorama = True
            else:
                print("Can't get model", file=sys.stderr)
        except pan.xapi.PanXapiError as e:
            print('pan.xapi.PanXapi:', e, file=sys.stderr)
            sys.exit(1)

    if (args.delete or args.add or args.add_roots or
       args.commit) and xapi is None:
        print('--tag argument required', file=sys.stderr)
        sys.exit(1)

    if args.delete:
        delete_certs(xapi)

    if args.add or args.add_roots:
        total = {
            'root': 0,
            'intermediate': 0,
        }
        try:
            with tarfile.open(name=args.certs, mode='r') as tar:
                for member in tar:
                    if args.verbose:
                        print('extracted %s' % member.name,
                              file=sys.stderr)
                    cert_name, cert_type = parse_cert(member.name)
                    f = tar.extractfile(member)
                    content = f.read()
                    if add_cert(xapi, cert_name, cert_type, content):
                        total[cert_type] += 1
        except (tarfile.TarError, OSError) as e:
            print("tarfile %s: %s" % (args.certs, e), file=sys.stderr)
            sys.exit(1)

        for x in total:
            if total[x] > 0:
                print('%d %s certificates added' % (total[x], x))

    if args.commit:
        commit(xapi)


def parse_cert(path):
    pat = (r'^\d{4,4}_[().\w-]+/(intermediate|root)/'
           r'[0-9A-F]{64,64}\.crt$')
    if not re.search(pat, path):
        print('malformed path in archive: %s' % path,
              file=sys.stderr)
        sys.exit(1)

    head, crt = os.path.split(path)
    name, cert_type = os.path.split(head)
    cert_name = name[:4] + '-' + crt[:64]

    # PAN-OS certificate-name max len 63
    # Panorama certificate-name max len 31
    # PAN-99186 won't do
    return cert_name[:31], cert_type


def delete_certs(xapi):
    if args.vsys:
        xpath_panos = ("/config/devices/entry[@name='localhost.localdomain']"
                       "/vsys/entry[@name='%s']/certificate") % args.vsys
        xpath2_panos = ("/config/devices/entry[@name='localhost.localdomain']"
                        "/vsys/entry[@name='%s']/ssl-decrypt/trusted-root-CA"
                        "/member[text()='%s']")
    else:
        xpath_panos = '/config/shared/certificate'
        xpath2_panos = ("/config/shared/ssl-decrypt/trusted-root-CA"
                        "/member[text()='%s']")
    xpath_panorama = '/config/panorama/certificate'
    xpath2_panorama = ("/config/panorama/ssl-decrypt/trusted-root-CA"
                       "/member[text()='%s']")

    pat = r'^\d{4,4}-[0-9A-F]{26,26}$'

    xpath = xpath_panorama if panorama else xpath_panos
    kwargs = {'xpath': xpath}
    api_request(xapi, xapi.get, kwargs, 'success', '19')

    total = 0
    entries = xapi.element_root.findall('./result/certificate/entry')
    for entry in entries:
        name = entry.attrib['name']
        if re.search(pat, name):
            if panorama:
                xpath2 = xpath2_panorama % name
            elif args.vsys:
                xpath2 = xpath2_panos % (args.vsys, name)
            else:
                xpath2 = xpath2_panos % name
            kwargs = {'xpath': xpath2}
            api_request(xapi, xapi.delete, kwargs, 'success', ['7', '20'])

            xpath2 = xpath + "/entry[@name='%s']" % name
            kwargs = {'xpath': xpath2}
            api_request(xapi, xapi.delete, kwargs, 'success', '20')

            total += 1
            if args.verbose:
                print('deleted', name, file=sys.stderr)

    print('%d certificates deleted' % total)


def add_cert(xapi, cert_name, cert_type, content):
    if (cert_type == 'root' and not args.add_roots or
       cert_type == 'intermediate' and not args.add):
        return False

    kwargs = {
        'category': 'certificate',
        'file': content,
        'extra_qs': {
            'certificate-name': cert_name,
            'format': 'pem',
        },
    }
    if args.vsys is not None:
        kwargs['vsys'] = args.vsys

    api_request(xapi, xapi.import_file, kwargs, 'success')

    if args.vsys:
        xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                 "/vsys/entry[@name='%s']/ssl-decrypt"
                 "/trusted-root-CA") % args.vsys
    elif panorama:
        xpath = '/config/panorama/ssl-decrypt/trusted-root-CA'
    else:
        xpath = '/config/shared/ssl-decrypt/trusted-root-CA'

    element = '<member>%s</member>' % cert_name

    kwargs = {
        'xpath': xpath,
        'element': element,
    }

    api_request(xapi, xapi.set, kwargs, 'success', '20')

    if args.verbose:
        print('added %s %s' % (cert_type, cert_name), file=sys.stderr)

    return True


def api_request(xapi, func, kwargs, status=None, status_code=None):
    try:
        func(**kwargs)
    except pan.xapi.PanXapiError as e:
        print('%s: %s: %s' % (func.__name__, kwargs, e),
              file=sys.stderr)
        sys.exit(1)

    if status is not None and not s1_in_s2(xapi.status, status):
        print('%s: %s: status %s != %s' %
              (func.__name__, kwargs,
               xapi.status, status),
              file=sys.stderr)
        sys.exit(1)

    if (status_code is not None and
       not s1_in_s2(xapi.status_code, status_code)):
        print('%s: %s: status_code %s != %s' %
              (func.__name__, kwargs,
               xapi.status_code, status_code),
              file=sys.stderr)
        sys.exit(1)


def commit(xapi):
    root = etree.Element('commit')
    desc = etree.SubElement(root, 'description')
    desc.text = '%s %s' % (title, __version__)
    if args.admin:
        admin = etree.SubElement(root, 'admin')
        admin_member = etree.SubElement(admin, 'member')
        admin_member.text = args.admin
    partial = etree.SubElement(root, 'partial')

    policy_and_objects = etree.Element('policy-and-objects')
    policy_and_objects.text = 'excluded'
    device_and_network = etree.Element('device-and-network')
    device_and_network.text = 'excluded'
    shared_object = etree.Element('shared-object')
    shared_object.text = 'excluded'

    if args.vsys:
        vsys = etree.SubElement(partial, 'vsys')
        vsys_member = etree.SubElement(vsys, 'member')
        vsys_member.text = args.vsys
        partial.append(device_and_network)
        partial.append(shared_object)
    elif panorama:
        partial.append(shared_object)
    else:
        partial.append(device_and_network)
        partial.append(policy_and_objects)

    cmd = etree.tostring(root).decode()
    if args.verbose:
        print(cmd, file=sys.stderr)

    kwargs = {
        'cmd': cmd,
        'sync': True,
    }

    print('commit config for admin %s' % args.admin)
    api_request(xapi, xapi.commit, kwargs, 'success')
    if args.verbose:
        print(xapi.xml_root(), file=sys.stderr)

    if xapi.status_code is not None:
        code = ' [code=\"%s\"]' % xapi.status_code
    else:
        code = ''
    if xapi.status is not None:
        print('commit: %s%s' % (xapi.status, code), end='')
    if xapi.status_detail is not None:
        print(': "%s"' % xapi.status_detail.rstrip(), end='')
    print()


def s1_in_s2(s1, s2):
    if isinstance(s2, str):
        return s1 == s2
    elif isinstance(s2, list):
        return s1 in s2
    else:
        raise ValueError('Invalid type for s2. '
                         'Must be a string or a list of strings.')


def parse_args():
    def check_vsys(x):
        if x.isdigit():
            x = 'vsys' + x
        return x

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options]',
        description='preload PAN-OS intermediate CAs')
    parser.add_argument('--tag', '-t',
                        help='.panrc tagname')
    parser.add_argument('--vsys',
                        type=check_vsys,
                        help='vsys name or number')
    x = 'certificates.tgz'
    parser.add_argument('--certs',
                        default=x,
                        metavar='PATH',
                        help='PAN-OS certificate archive path'
                        ' (default: %s)' % x)
    parser.add_argument('--add',
                        action='store_true',
                        help='add intermediate certificates')
    parser.add_argument('--add-roots',
                        action='store_true',
                        help='add root certificates (experimental)')
    parser.add_argument('--delete',
                        action='store_true',
                        help='delete previously added certificates')
    parser.add_argument('--commit',
                        action='store_true',
                        help='commit configuration')
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
    x = '%s %s' % (title, __version__)
    parser.add_argument('--version',
                        action='version',
                        help='display version',
                        version=x)
    args = parser.parse_args()

    if args.verbose:
        print(args, file=sys.stderr)

    return args


if __name__ == '__main__':
    main()
