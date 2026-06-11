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

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional


def _as_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _as_str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


@dataclass
class ErrorInfo:
    code: Optional[str] = None
    message: Optional[str] = None
    detail_type: Optional[str] = None
    detail_messages: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []

        if self.code:
            parts.append(self.code)
        if self.message:
            parts.append(self.message)
        if self.detail_type:
            parts.append(self.detail_type)
        parts.extend(self.detail_messages)

        return ': '.join(parts)


@dataclass
class ParsedResponse:
    raw: str
    obj: Optional[Dict[str, Any]] = field(init=False, default=None)
    kind: str = field(init=False, default='non_json')
    request_id: Optional[str] = field(init=False, default=None)
    errors: List[ErrorInfo] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        try:
            parsed = json.loads(self.raw)
        except json.JSONDecodeError:
            return

        if not isinstance(parsed, dict):
            self.kind = 'json'
            return

        self.obj = parsed
        self.request_id = _as_str(parsed.get('_request_id'))
        self._parse(parsed)

    @property
    def is_json(self) -> bool:
        return self.kind != 'non_json'

    @property
    def has_errors(self) -> bool:
        return len(self.errors) != 0

    def summary(self) -> str:
        parts = []

        if self.errors:
            s = self.errors[0].summary()
            if s:
                parts.append(s)

        if self.request_id:
            parts.append('request_id=%s' % self.request_id)

        return ': '.join(parts) if parts else self.raw

    def short_summary(self) -> str:
        parts = []

        if self.errors:
            err = self.errors[0]

            if err.code:
                parts.append(err.code)

            if err.detail_messages:
                parts.append(err.detail_messages[0])
            elif err.message:
                parts.append(err.message)

        if self.request_id:
            parts.append('request_id=%s' % self.request_id)

        return ': '.join(parts) if parts else self.raw

    def _parse(self, obj: Dict[str, Any]) -> None:
        errors = obj.get('_errors')
        if isinstance(errors, list):
            self.kind = 'scm_errors'
            for item in errors:
                if isinstance(item, dict):
                    self.errors.append(self._parse_scm_error(item))
            return

        fault = obj.get('fault')
        if isinstance(fault, dict):
            self.kind = 'fault'

            detail = fault.get('detail')
            if not isinstance(detail, dict):
                detail = {}

            self.errors.append(
                ErrorInfo(
                    code=_as_str(detail.get('errorcode')),
                    message=_as_str(fault.get('faultstring')),
                    detail_type=_as_str(detail.get('reason')),
                )
            )
            return

        msg = _as_str(obj.get('msg'))
        if msg is not None:
            self.kind = 'msg'
            self.errors.append(ErrorInfo(message=msg))
            return

        self.kind = 'json'

    def _parse_scm_error(self, item: Dict[str, Any]) -> ErrorInfo:
        err = ErrorInfo(
            code=_as_str(item.get('code')),
            message=_as_str(item.get('message')),
        )

        details = item.get('details')
        if isinstance(details, dict):
            err.detail_type = _as_str(details.get('errorType'))
            err.detail_messages.extend(_as_str_list(details.get('message')))

            suberrors = details.get('errors')
            if isinstance(suberrors, list):
                for sub in suberrors:
                    if not isinstance(sub, dict):
                        continue

                    sub_type = _as_str(sub.get('type'))
                    sub_msg = (_as_str(sub.get('message')) or
                               _as_str(sub.get('msg')))

                    if sub_type and sub_msg:
                        err.detail_messages.append(
                            '%s: %s' % (sub_type, sub_msg))
                    elif sub_msg:
                        err.detail_messages.append(sub_msg)
                    elif sub_type:
                        err.detail_messages.append(sub_type)

        elif isinstance(details, list):
            err.detail_messages.extend(_as_str_list(details))

        return err


if __name__ == '__main__':
    import pathlib
    import sys
    if not (len(sys.argv) > 1 and sys.argv[1]):
        sys.exit(1)

    path = pathlib.Path(sys.argv[1])
    try:
        with path.open('r') as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        print('%s: %s' % (path, e), file=sys.stderr)
        sys.exit(1)

    for idx, item in enumerate(obj.get('scm_errors', [])):
        if isinstance(item, dict):
            text = json.dumps(item)
        elif isinstance(item, str):
            text = item
        else:
            print(f'{idx + 1} not handled type: {type(item).__name__}: {item}',
                  file=sys.stderr)
            continue
        r = ParsedResponse(text)
        print(f'{idx + 1} {r.raw}')
        print(f'json {r.is_json} has_errors {r.has_errors}')
        print('ParsedResponse summary', r.summary())
        print('ParsedResponse short_summary', r.short_summary())
        for e in r.errors:
            print('ErrorInfo summary', e.summary())
        print()
