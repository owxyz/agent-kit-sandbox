"""Runs in the PR container. Exposes one PR module over stdin/stdout as JSON lines.

This process holds untrusted code, so nothing here is relied on for security. The
host broker checks every frame.
"""
import importlib
import json
import os
import sys
import traceback


def main():
    # Keep the real pipe for frames, so that PR prints can't corrupt the protocol.
    frames_in = os.fdopen(os.dup(0), "rb")
    frames_out = os.dup(1)
    os.dup2(2, 1)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)

    def send(frame):
        os.write(frames_out, (json.dumps(frame, allow_nan=False) + "\n").encode())

    try:
        target = importlib.import_module(os.environ["HELDOUT_TARGET"])
    except Exception:
        traceback.print_exc()
        return 3
    send({"ready": True})
    for line in frames_in:
        request = json.loads(line)
        reply = {"id": request["id"]}
        try:
            function = getattr(target, request["fn"])
            value = function(*request.get("args", []), **request.get("kwargs", {}))
            json.dumps(value, allow_nan=False)
            reply["ok"] = value
        except Exception as error:  # Includes results that aren't plain JSON.
            reply["raise"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        send(reply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
