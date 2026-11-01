"""Native operator provisioning; never a Loop/ordinary SDK credential API."""

import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile

from ..domain.errors import ErrorCode, StableError
from ..domain.ids import validate_id
from .credentials import WindowsCredentialStore, InsecureDevCredentialStore, open_key_store, operator_signing_authority
from .crypto import verify_signature
from .private_paths import require_private_path, secure_private_path
from .store.connection import APPLICATION_ID, USER_VERSION


def open_provider_store(data_dir, *, realm_id='realm://main', allow_insecure=False, create=False):
    """A provider-only directory; a worker never needs the Root/Service store."""
    root=Path(data_dir).absolute()
    for part in (root,*root.parents):
        if part.is_symlink() or part.is_junction():
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='credential data path cannot contain a reparse point')
    require_private_path(root)
    validate_id(realm_id)
    if not realm_id.startswith('realm://'):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider store requires a RealmId')
    owner_store,_=open_key_store(root,allow_insecure=allow_insecure)
    cls=WindowsCredentialStore if owner_store.profile==WindowsCredentialStore.profile else InsecureDevCredentialStore
    parent=root/'keys'/'providers'
    if create:
        if parent.is_symlink() or parent.is_junction():
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='Provider store cannot be a reparse point')
        parent.mkdir(exist_ok=True)
        secure_private_path(parent)
    require_private_path(parent)
    slot=hashlib.sha256(realm_id.encode('utf-8')).hexdigest()
    return cls(parent/slot,create=create)


def _operator_identity(data_dir,realm_id,operator):
    """Native Authority enforcement read, never an ordinary CLI store mutation."""
    path=Path(data_dir).absolute()/'meta.db'
    try:
        if not path.is_file() or path.is_symlink() or path.is_junction():
            raise ValueError('missing committed Runtime')
        conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)
        try:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('PRAGMA trusted_schema=OFF')
            if conn.execute('PRAGMA application_id').fetchone()[0]!=APPLICATION_ID or conn.execute('PRAGMA user_version').fetchone()[0]!=USER_VERSION:
                raise ValueError('unsupported Runtime metadata identity')
            row=conn.execute("SELECT p.principal_id,p.public_identity_json,g.status,g.epoch_id,r.epoch_id "
                "FROM realms r JOIN epochs e ON e.epoch_id=r.epoch_id AND e.realm_id=r.realm_id "
                "JOIN principals p ON p.principal_id=e.authority_root_principal_id AND p.realm_id=r.realm_id "
                "JOIN authority_grants g ON g.grant_id=? AND g.subject_id=p.principal_id "
                "WHERE r.realm_id=? AND e.status='ACTIVE' AND p.status='ACTIVE' AND p.kind='OPERATOR_ROOT'",
                (operator['authority_grant_id'],realm_id)).fetchone()
        finally:
            conn.close()
        if row is None or row[0]!=operator['actor_id'] or row[2]!='ACTIVE' or row[3]!=row[4]:
            raise ValueError('current Root operator required')
        identity=json.loads(row[1])
        if identity['algorithm']!='Ed25519' or identity['public_key_hex']!=operator['public_key_hex']:
            raise ValueError('operator public identity differs')
        return bytes.fromhex(identity['public_key_hex'])
    except (OSError,ValueError,TypeError,KeyError,sqlite3.Error):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='credential provisioning requires the initialized current Realm Root operator') from None


def provision_provider_credential(data_dir, material, *, realm_id='realm://main', allow_insecure=False, previous_handle=None):
    """Create/verify one new item; rotation never deletes or rebinds the old item.

    The CLI owns its mutable material buffer and clears it on all exits. Secret
    material is never an ordinary command, Artifact, Fact, or return value.
    """
    candidate=None
    store=None
    published=False
    try:
        if type(material) is not bytearray or not 16<=len(material)<=8192 or re.fullmatch(rb'[A-Za-z0-9._~+/-]+=*',material) is None:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider credential material does not match the supported token format')
        operator,signer=operator_signing_authority(Path(data_dir),allow_insecure=allow_insecure)
        public_key=_operator_identity(data_dir,realm_id,operator)
        challenge=b'agent-meta-provider-provisioning/v1\0'+secrets.token_bytes(32)
        if not verify_signature(public_key,challenge,signer(challenge)):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='operator credential challenge failed')
        store=open_provider_store(data_dir,realm_id=realm_id,allow_insecure=allow_insecure,create=True)
        if previous_handle is not None:
            with store.get_for_scoped_use(previous_handle,purpose='provider'):
                pass
        # Publish only a completely written, verified item. Backups/readers
        # ignore this reserved staging directory and never observe a partial
        # final item. A hard link publishes atomically without overwriting.
        with tempfile.TemporaryDirectory(dir=store.root,prefix='.provisioning-') as staging:
            stage_path=Path(staging)
            if not stage_path.resolve().is_relative_to(store.root.resolve()):
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='Provider staging escaped its storage scope')
            temporary=type(store)(stage_path,create=True)
            candidate=temporary.create(material,purpose='provider')
            with temporary.get_for_scoped_use(candidate,purpose='provider') as verified:
                if not hmac.compare_digest(material,verified):
                    raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='new Provider credential verification failed')
            files=list(stage_path.iterdir())
            if len(files)!=1 or not files[0].is_file():
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='Provider staging item is invalid')
            os.link(files[0],store.root/files[0].name)
            published=True
            with store.get_for_scoped_use(candidate,purpose='provider') as verified:
                if not hmac.compare_digest(material,verified):
                    raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='published Provider credential verification failed')
            if os.name!='nt':
                fd=os.open(store.root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        return {'credential_handle':candidate,'credential_profile':store.profile,'purpose':'provider'}
    except BaseException as exc:
        if store is not None and candidate is not None and published:
            # A newly generated handle has not escaped this call or entered any
            # approved binding. Never delete the caller's previous handle.
            store.delete_metadata(candidate,reference_count=0)
        if isinstance(exc,OSError):
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE,message='atomic Provider credential storage failed') from None
        raise
    finally:
        if isinstance(material,bytearray):
            material[:]=b'\0'*len(material)
