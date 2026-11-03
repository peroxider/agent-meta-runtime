"""The producer must enforce ceilings before Session encodes or sends output."""
from agent_meta_runtime.adapters.scratch_kernel_process import KernelOutputGuard


class RecordingSession:
    def __init__(self):
        self.messages = []

    def send(self, stream, kind, content=None, parent=None, ident=None, **options):
        self.messages.append((stream,kind,content,parent,ident,options))
        return self.messages[-1]


def guarded_session():
    session,guard = RecordingSession(),KernelOutputGuard()
    guard.wrap(session)
    guard.begin({'header':{'msg_id':'cell-1'}})
    return session,guard


def test_positional_routing_identity_survives_guard_and_shutdown_is_forwarded():
    session,_ = guarded_session()
    parent = {'header':{'msg_id':'shutdown-1'}}
    session.send('control','shutdown_reply',{'status':'ok'},parent,[b'identity'])
    assert session.messages==[('control','shutdown_reply',{'status':'ok'},parent,[b'identity'],{})]


def test_dictionary_stream_is_bounded_and_other_cell_output_is_dropped():
    session,_ = guarded_session()
    for cell in ('other-cell','cell-1'):
        session.send('iopub',{'header':{'msg_type':'stream'},'parent_header':{'msg_id':cell},
            'content':{'name':'stdout','text':'x'*1200000}})
    assert len(session.messages)==1
    assert len(session.messages[0][2]['text'].encode())<=1048576
    session.send('shell','execute_reply',{'status':'ok'}, {'msg_id':'cell-1'})
    assert session.messages[-1][2]['scratch_output']['stdout_truncated'] is True


def test_exception_and_editor_payload_are_removed_before_transport():
    session,_ = guarded_session()
    parent = {'msg_id':'cell-1'}
    content = {'status':'error','ename':'ValueError','evalue':'SECRET',
        'traceback':['SECRET'],'payload':[{'source':'set_next_input','text':'SECRET'*1000000}]}
    session.send('shell','execute_reply',content,parent)
    reply = session.messages[-1][2]
    assert reply['ename']=='ValueError' and reply['evalue']=='' and reply['traceback']==[]
    assert reply['payload']==[] and 'SECRET' not in str(reply)
    assert content['evalue']=='SECRET'  # Do not mutate ipykernel's original reply.


def test_display_updates_are_immutable_mime_snapshots_without_metadata_handles():
    session,_ = guarded_session()
    session.send('iopub','update_display_data',{'data':{'text/plain':'42'},
        'metadata':{'secret':'SECRET'},'transient':{'display_id':'SECRET'}},
        {'msg_id':'cell-1'},metadata={'secret':'SECRET'})
    message = session.messages[-1]
    assert message[1]=='display_data' and message[2]=={'data':{'text/plain':'42'},'metadata':{}}
    assert message[-1]=={'metadata':{}} and 'SECRET' not in str(message)
