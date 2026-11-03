"""Bounded CPython binding-write tracking, active only during a trusted cell.

Values are never retained. The trace reads builtin frame/code attributes and
records STORE_NAME/STORE_GLOBAL in the actual user namespace. Heap mutation
remains UNKNOWN_RISK; this is not a general Python mutation monitor or sandbox.
"""

import dis
import sys

_GET_TRACE, _SET_TRACE = sys.gettrace, sys.settrace


class BindingWriteTrace:
    def __init__(self, namespace):
        self.namespace = namespace
        self.writes = set()
        self.complete = True
        self._instructions = {}
        self._previous = None
        self._callback = self._trace
        self._supported = sys.version_info[:2] == (3, 12)

    def _trace(self, frame, event, argument):
        if event == "call":
            if (
                frame.f_globals is not self.namespace
                and frame.f_locals is not self.namespace
            ):
                return None
            frame.f_trace_lines = False
            frame.f_trace_opcodes = True
        elif event in ("opcode", "exception"):
            code = frame.f_code
            cached = self._instructions.get(id(code))
            instructions = (
                cached[1] if cached is not None and cached[0] is code else None
            )
            if instructions is None:
                if (
                    len(self._instructions) >= 128
                    or len(code.co_code) > 4 * 1024 * 1024
                ):
                    self.complete = False
                    return self._callback
                # dis.get_instructions formats constants with repr. Decode
                # only name-store opcodes, never touch arbitrary co_consts or
                # hash/compare a user-created code object's constants.
                instructions, extension = {}, 0
                raw, names = code.co_code, code.co_names
                wanted = {
                    dis.opmap[name]: name
                    for name in (
                        "STORE_NAME",
                        "DELETE_NAME",
                        "STORE_GLOBAL",
                        "DELETE_GLOBAL",
                    )
                }
                for offset in range(0, len(raw), 2):
                    opcode, argument_byte = raw[offset], raw[offset + 1]
                    argument_index = extension | argument_byte
                    if opcode == dis.EXTENDED_ARG:
                        extension = argument_index << 8
                        continue
                    if opcode in wanted and argument_index < len(names):
                        instructions[offset] = (wanted[opcode], names[argument_index])
                    extension = 0
                self._instructions[id(code)] = (code, instructions)
            operation, name = instructions.get(frame.f_lasti, (None, None))
            relevant = (
                operation in ("STORE_NAME", "DELETE_NAME")
                and frame.f_locals is self.namespace
                or operation in ("STORE_GLOBAL", "DELETE_GLOBAL")
                and frame.f_globals is self.namespace
            )
            if relevant:
                if event == "exception":
                    self.complete = False
                elif type(name) is str and len(name) <= 128 and name.isidentifier():
                    if len(self.writes) < 4096:
                        self.writes.add(name)
                    else:
                        self.complete = False
        return self._callback

    def __enter__(self):
        self._previous = _GET_TRACE()
        if not self._supported:
            self.complete = False
            return self
        if self._previous is not None:
            self.complete = False
        _SET_TRACE(self._callback)
        return self

    def __exit__(self, *_):
        if not self._supported:
            return
        self.complete = self.complete and _GET_TRACE() is self._callback
        _SET_TRACE(self._previous)
        self._instructions.clear()
