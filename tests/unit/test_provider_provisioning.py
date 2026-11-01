"""Actual native credential creation/rotation; synthetic material only."""

from contextlib import contextmanager
import io
import json
import os
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agent_meta_runtime.adapters.credentials import open_key_store
from agent_meta_runtime.adapters.provider_credentials import open_provider_store, provision_provider_credential
from agent_meta_runtime.adapters.private_paths import require_private_path
from agent_meta_runtime.adapters.store.backup import create_backup, restore_backup
from agent_meta_runtime.adapters.store.connection import connect_store
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.cli import provider_credentials as cli

SECRET=b'synthetic-provider-token-for-native-provisioning'
REPLACEMENT=b'synthetic-replacement-token-for-native-provisioning'


def initialized(root):
    run_init(root,insecure_dev_credential_file=os.name!='nt')


def options():
    return {'allow_insecure':os.name!='nt'}


def flags(root):
    return ['--data-dir',str(root),*(['--insecure-dev-credential-file'] if os.name!='nt' else [])]


def counts(root):
    conn=sqlite3.connect(root/'meta.db')
    try:
        return tuple(conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
            for table in ('facts','commands','authority_uses','tasks','invocations'))
    finally:
        conn.close()


def test_native_item_is_provider_only_realm_scoped_and_caller_material_is_cleared(tmp_path):
    initialized(tmp_path)
    before=counts(tmp_path)
    material=bytearray(SECRET)
    result=provision_provider_credential(tmp_path,material,**options())
    assert material==bytearray(len(SECRET)) and result['purpose']=='provider'
    assert counts(tmp_path)==before
    store=open_provider_store(tmp_path,**options())
    assert store.root.parent.name=='providers' and len(store.root.name)==64
    with store.get_for_scoped_use(result['credential_handle'],purpose='provider') as recovered:
        assert recovered==SECRET
    assert recovered==bytearray(len(SECRET))
    _,root_handles=open_key_store(tmp_path,**options())
    with pytest.raises(StableError):
        with store.get_for_scoped_use(root_handles['root'],purpose='provider'):
            raise AssertionError('Root key escaped into Provider store')
    other=open_provider_store(tmp_path,realm_id='realm://other',create=True,**options())
    with pytest.raises(StableError):
        with other.get_for_scoped_use(result['credential_handle'],purpose='provider'):
            raise AssertionError('credential crossed Realm storage scope')
    if os.name=='nt':
        assert all(SECRET not in path.read_bytes() for path in store.root.iterdir() if path.is_file())
        assert result['credential_profile']=='WINDOWS_DPAPI_CURRENT_USER'
    else:
        assert result['credential_profile']=='INSECURE_TEST_ONLY'


def test_rotation_returns_a_new_item_and_retains_old_references(tmp_path):
    initialized(tmp_path)
    first=provision_provider_credential(tmp_path,bytearray(SECRET),**options())
    material=bytearray(REPLACEMENT)
    second=provision_provider_credential(tmp_path,material,previous_handle=first['credential_handle'],**options())
    assert first['credential_handle']!=second['credential_handle'] and material==bytearray(len(REPLACEMENT))
    store=open_provider_store(tmp_path,**options())
    for result,expected in ((first,SECRET),(second,REPLACEMENT)):
        with store.get_for_scoped_use(result['credential_handle'],purpose='provider') as value:
            assert value==expected


@pytest.mark.parametrize('kind',['revoked','foreign_realm','partial'])
def test_no_item_is_created_without_the_current_initialized_root_operator(tmp_path,kind):
    initialized(tmp_path)
    if kind=='revoked':
        conn=sqlite3.connect(tmp_path/'meta.db')
        conn.execute("UPDATE principals SET status='REVOKED' WHERE kind='OPERATOR_ROOT'"); conn.commit(); conn.close()
    elif kind=='partial':
        # Retain a valid protected key store but remove the committed database.
        (tmp_path/'meta.db').unlink()
    material=bytearray(SECRET)
    with pytest.raises(StableError) as caught:
        provision_provider_credential(tmp_path,material,realm_id='realm://other' if kind=='foreign_realm' else 'realm://main',**options())
    assert caught.value.code==ErrorCode.AUTHORITY_DENIED
    assert material==bytearray(len(SECRET)) and not (tmp_path/'keys/providers').exists()


def test_failed_new_item_verification_cleans_only_the_unpublished_candidate(tmp_path,monkeypatch):
    initialized(tmp_path)
    original=provision_provider_credential(tmp_path,bytearray(SECRET),**options())
    store=open_provider_store(tmp_path,**options())
    before=set(store.root.iterdir())
    cls=type(store)
    real=cls.get_for_scoped_use
    @contextmanager
    def changed(self,handle,*,purpose):
        if self.root==store.root and handle!=original['credential_handle'] and purpose=='provider':
            yield bytearray(b'different-synthetic-material')
        else:
            with real(self,handle,purpose=purpose) as value:
                yield value
    monkeypatch.setattr(cls,'get_for_scoped_use',changed)
    material=bytearray(REPLACEMENT)
    with pytest.raises(StableError) as caught:
        provision_provider_credential(tmp_path,material,previous_handle=original['credential_handle'],**options())
    assert caught.value.code==ErrorCode.KEY_UNAVAILABLE and set(store.root.iterdir())==before
    assert material==bytearray(len(REPLACEMENT))


def test_settings_import_outputs_only_handle_and_never_copies_other_environment_values(tmp_path,capsys):
    initialized(tmp_path)
    path=tmp_path/'synthetic-settings.json'
    path.write_text(json.dumps({'env':{'ANTHROPIC_AUTH_TOKEN':SECRET.decode(),
        'UNRELATED_SECRET':'synthetic-unrelated-value','ANTHROPIC_BASE_URL':'https://not-contacted.invalid/compatible'}}))
    before=counts(tmp_path)
    assert cli.main([*flags(tmp_path),'--from-claude-settings',str(path)])==0
    output=capsys.readouterr()
    assert SECRET.decode() not in output.out+output.err and 'synthetic-unrelated-value' not in output.out+output.err
    assert 'not-contacted.invalid' not in output.out+output.err
    result=json.loads(output.out)['result']
    assert counts(tmp_path)==before and set(result)=={'credential_handle','credential_profile','purpose'}
    with open_provider_store(tmp_path,**options()).get_for_scoped_use(result['credential_handle'],purpose='provider') as material:
        assert material==SECRET


def test_stdin_import_is_bounded_and_ignores_provider_environment(tmp_path,monkeypatch,capsys):
    initialized(tmp_path)
    monkeypatch.setenv('ANTHROPIC_AUTH_TOKEN','synthetic-env-value-must-not-be-used')
    monkeypatch.setattr(cli.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(SECRET+b'\r\n'),isatty=lambda:False))
    assert cli.main([*flags(tmp_path),'--stdin'])==0
    output=capsys.readouterr()
    result=json.loads(output.out)['result']
    with open_provider_store(tmp_path,**options()).get_for_scoped_use(result['credential_handle'],purpose='provider') as material:
        assert material==SECRET
    assert SECRET.decode() not in output.out+output.err


@pytest.mark.parametrize('raw',[b'',b'a'*8195,b'synthetic-token\nembedded-newline',b'bad\x00token',b'too-short'])
def test_invalid_input_never_creates_an_item_or_echoes_material(tmp_path,monkeypatch,capsys,raw):
    initialized(tmp_path)
    monkeypatch.setattr(cli.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw),isatty=lambda:False))
    assert cli.main([*flags(tmp_path),'--stdin'])==2
    output=capsys.readouterr()
    assert json.loads(output.out)['error']['code']==ErrorCode.INVALID_ARGUMENT
    assert not (tmp_path/'keys/providers').exists()
    if raw:
        assert raw.decode(errors='replace') not in output.out+output.err


def test_argument_errors_do_not_echo_a_mistakenly_supplied_secret(capsys):
    with pytest.raises(SystemExit) as caught:
        cli.main(['--data-dir','unused','--stdin','--token',SECRET.decode()])
    assert caught.value.code==2
    output=capsys.readouterr()
    assert SECRET.decode() not in output.out+output.err


def test_linux_fixture_storage_requires_explicit_opt_in(tmp_path,monkeypatch,capsys):
    initialized(tmp_path)
    monkeypatch.setattr(cli.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(SECRET),isatty=lambda:False))
    if os.name=='nt':
        assert cli.main(['--data-dir',str(tmp_path),'--stdin'])==0
        assert json.loads(capsys.readouterr().out)['result']['credential_profile']=='WINDOWS_DPAPI_CURRENT_USER'
    else:
        assert cli.main(['--data-dir',str(tmp_path),'--stdin'])==8
        assert not (tmp_path/'keys/providers').exists()
        assert json.loads(capsys.readouterr().out)['ok'] is False


def test_isolated_native_cli_process_imports_over_stdin_without_secret_in_argv_or_output(tmp_path):
    initialized(tmp_path)
    args=[sys.executable,'-I','-m','agent_meta_runtime.interfaces.cli.provider_credentials',*flags(tmp_path),'--stdin']
    assert all(SECRET.decode() not in item for item in args)
    result=subprocess.run(args,input=SECRET,capture_output=True,timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    assert result.returncode==0 and SECRET not in result.stdout+result.stderr
    handle=json.loads(result.stdout)['result']['credential_handle']
    with open_provider_store(tmp_path,**options()).get_for_scoped_use(handle,purpose='provider') as material:
        assert material==SECRET


def test_backup_restore_retains_published_provider_items_and_private_realm_directories(tmp_path):
    source=tmp_path/'source'
    initialized(source)
    first=provision_provider_credential(source,bytearray(SECRET),**options())
    second=provision_provider_credential(source,bytearray(REPLACEMENT),previous_handle=first['credential_handle'],**options())
    store=open_provider_store(source,**options())
    unfinished=store.root/'.provisioning-synthetic-interrupted'
    unfinished.mkdir()
    (unfinished/'partial').write_bytes(b'synthetic-unpublished-ciphertext-fragment')
    conn=connect_store(source/'meta.db')
    try:
        backup=tmp_path/'backup'
        outcome=create_backup(conn,source,backup)
    finally:
        conn.close()
    paths=[entry['relpath'] for entry in outcome.manifest['files']]
    assert len([path for path in paths if path.startswith('keys/providers/')])==2
    assert not any('.provisioning-' in path for path in paths)
    restored=tmp_path/'restored'
    restore_backup(backup,restored)
    recovered=open_provider_store(restored,**options())
    for folder in (restored/'keys',restored/'keys/providers',recovered.root):
        require_private_path(folder)
    for result,expected in ((first,SECRET),(second,REPLACEMENT)):
        with recovered.get_for_scoped_use(result['credential_handle'],purpose='provider') as material:
            assert material==expected


def test_failed_atomic_publication_never_deletes_or_replaces_an_existing_handle(tmp_path,monkeypatch):
    initialized(tmp_path)
    first=provision_provider_credential(tmp_path,bytearray(SECRET),**options())
    store=open_provider_store(tmp_path,**options())
    before={path.name:path.read_bytes() for path in store.root.iterdir() if path.is_file()}
    def occupied(*args,**kwargs):
        raise FileExistsError('synthetic atomic publish refusal')
    monkeypatch.setattr('agent_meta_runtime.adapters.provider_credentials.os.link',occupied)
    material=bytearray(REPLACEMENT)
    with pytest.raises(StableError) as caught:
        provision_provider_credential(tmp_path,material,previous_handle=first['credential_handle'],**options())
    assert caught.value.code==ErrorCode.KEY_UNAVAILABLE
    assert {path.name:path.read_bytes() for path in store.root.iterdir() if path.is_file()}==before
    assert material==bytearray(len(REPLACEMENT))
