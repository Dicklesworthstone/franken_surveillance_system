"""Bounded laboratory-only syslog/child-output pump; never contacts a camera."""

import os
import selectors
import subprocess
import time


class LabLogPump:
    def __init__(self, log, max_messages=128, max_bytes=65536):
        self.log = log
        self.log.setblocking(False)
        self.messages = []
        self.retained_bytes = 0
        self.omitted_messages = 0
        self.max_messages = max_messages
        self.max_bytes = max_bytes

    def drain(self):
        # Bound each turn even if an oracle emits logs continuously.
        for _ in range(64):
            try:
                message = self.log.recv(4096)
            except BlockingIOError:
                break
            if (len(self.messages) < self.max_messages
                    and self.retained_bytes + len(message) <= self.max_bytes):
                self.messages.append(message)
                self.retained_bytes += len(message)
            else:
                self.omitted_messages += 1

    def pause(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.drain()
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def wait(self, process, timeout):
        """Drain both pipes and logs while awaiting an owned child.

        Output capture is capped per pipe, but excess is still consumed. On
        timeout the caller retains responsibility for stopping and joining the
        child; this helper never signals another process.
        """
        deadline = time.monotonic() + timeout
        output = {"stdout": bytearray(), "stderr": bytearray()}
        omitted = {"stdout": 0, "stderr": 0}
        with selectors.DefaultSelector() as selector:
            for name in output:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                self.drain()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout)
                for key, _ in selector.select(min(0.01, remaining)):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    kept = data[:max(0, self.max_bytes - len(output[key.data]))]
                    output[key.data].extend(kept)
                    omitted[key.data] += len(data) - len(kept)
        self.drain()
        result = subprocess.CompletedProcess(process.args, process.wait(),
                                             bytes(output["stdout"]), bytes(output["stderr"]))
        result.omitted_bytes = omitted
        return result
