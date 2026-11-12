"""Test-side client. Held-out tests call PR code only through target().

    import heldout_client
    payments = heldout_client.target()
    assert payments.fee_cents(1000) == 59

Arguments and results are plain JSON. A PR exception is re-raised as the builtin
exception of the same name, or as RemoteError when no builtin matches.
"""
import builtins
import json
import os

RPC_IN = 3
RPC_OUT = 4


class RemoteError(Exception):
    def __init__(self, kind, message):
        super().__init__("%s: %s" % (kind, message))
        self.kind = kind


class AdapterGone(Exception):
    """The PR side failed, stopped or broke the protocol."""


_buffer = bytearray()


def _read_line():
    while b"\n" not in _buffer:
        chunk = os.read(RPC_IN, 65536)
        if not chunk:
            raise AdapterGone("broker closed the channel")
        _buffer.extend(chunk)
    index = _buffer.index(b"\n")
    line = bytes(_buffer[:index])
    del _buffer[: index + 1]
    return line


def call(function, *args, **kwargs):
    frame = json.dumps({"fn": function, "args": args, "kwargs": kwargs}).encode() + b"\n"
    while frame:
        frame = frame[os.write(RPC_OUT, frame):]
    reply = json.loads(_read_line())
    if "fatal" in reply:
        raise AdapterGone(reply["fatal"])
    if "raise" in reply:
        kind, message = reply["raise"]["type"], reply["raise"]["message"]
        builtin = getattr(builtins, kind, None)
        if isinstance(builtin, type) and issubclass(builtin, Exception):
            raise builtin(message)
        raise RemoteError(kind, message)
    return reply["ok"]


class _Target:
    def __getattr__(self, name):
        def invoke(*args, **kwargs):
            return call(name, *args, **kwargs)
        return invoke


def target():
    return _Target()
