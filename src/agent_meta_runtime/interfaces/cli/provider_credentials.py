"""Native operator credential provisioning, separate from ordinary API CLI.

Reads only an explicit bounded stdin/config source. Material goes directly to
the enforcement Credential Store; output contains a handle and security profile.
"""

import argparse
import json
from pathlib import Path
import sys

from ...adapters.provider_credentials import provision_provider_credential
from ...domain.errors import ErrorCode, StableError


class _Parser(argparse.ArgumentParser):
    def error(self,message):
        # Unknown arguments might be a mistakenly supplied token. Never echo
        # arbitrary argv values into diagnostics.
        self.exit(2,'invalid credential provisioning arguments; use --help\n')


def _read_buffer(stream,maximum):
    buffer=bytearray(maximum+1)
    used=0
    view=memoryview(buffer)
    try:
        while used<=maximum:
            count=stream.readinto(view[used:])
            if type(count) is not int or not 0<=count<=len(buffer)-used:
                raise ValueError('invalid source read')
            if count==0:
                break
            used+=count
        if used>maximum:
            raise ValueError('source exceeds limit')
    except BaseException:
        buffer[:]=b'\0'*len(buffer)
        raise
    finally:
        view.release()
    del buffer[used:]
    return buffer


def _pairs(items):
    value={}
    for key,item in items:
        if key in value:
            raise ValueError('duplicate source field')
        value[key]=item
    return value


def _material(args):
    raw=None
    document=token=None
    try:
        if args.stdin:
            if sys.stdin.isatty():
                raise ValueError('stdin must be a bounded pipe, not an echoing terminal')
            raw=_read_buffer(sys.stdin.buffer,8194)
            if raw.endswith(b'\r\n'):
                del raw[-2:]
            elif raw.endswith(b'\n'):
                del raw[-1:]
            material=raw
            raw=None
            return material
        path=args.from_claude_settings.expanduser()
        if not path.is_file() or path.stat().st_size>1024*1024:
            raise ValueError('source unavailable or oversized')
        with path.open('rb') as stream:
            raw=_read_buffer(stream,1024*1024)
        document=json.loads(raw,object_pairs_hook=_pairs)
        environment=document.get('env') if isinstance(document,dict) else None
        token=environment.get('ANTHROPIC_AUTH_TOKEN') if isinstance(environment,dict) else None
        if not isinstance(token,str):
            raise ValueError('source token unavailable')
        return bytearray(token,'ascii')
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider credential source is invalid or unavailable') from None
    finally:
        if raw is not None:
            raw[:]=b'\0'*len(raw)
        document=token=None


def build_parser():
    parser=_Parser(prog='agent-meta-provider-credential',description=__doc__)
    parser.add_argument('--data-dir',type=Path,required=True)
    parser.add_argument('--realm',default='realm://main')
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--stdin',action='store_true',help='read token bytes from a noninteractive pipe')
    source.add_argument('--from-claude-settings',type=Path,help='read only env.ANTHROPIC_AUTH_TOKEN from this explicit file')
    parser.add_argument('--previous-handle',default=None,help='create a replacement item while retaining the old provider item')
    parser.add_argument('--insecure-dev-credential-file',action='store_true',help='explicit fixture-only storage; never product security')
    return parser


def main(argv=None):
    args=build_parser().parse_args(argv)
    try:
        material=_material(args)
        result=provision_provider_credential(args.data_dir,material,realm_id=args.realm,
            allow_insecure=args.insecure_dev_credential_file,previous_handle=args.previous_handle)
        print(json.dumps({'schema':'provider-provisioning/v1','ok':True,'result':result},sort_keys=True),flush=True)
        return 0
    except StableError as exc:
        print(json.dumps({'schema':'provider-provisioning/v1','ok':False,'error':{'code':exc.code,'message':exc.message}},sort_keys=True),flush=True)
        return {ErrorCode.INVALID_ARGUMENT:2,ErrorCode.AUTHORITY_DENIED:3,ErrorCode.FEATURE_UNAVAILABLE:6,
            ErrorCode.KEY_UNAVAILABLE:8}.get(exc.code,70)
    except (Exception,KeyboardInterrupt):
        print(json.dumps({'schema':'provider-provisioning/v1','ok':False,
            'error':{'code':ErrorCode.INTERNAL,'message':'Provider credential provisioning failed'}},sort_keys=True),flush=True)
        return 70


if __name__=='__main__':
    raise SystemExit(main())
