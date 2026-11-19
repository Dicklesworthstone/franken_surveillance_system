"""Synthetic processes only: backpressure, bounded capture and timeout ownership."""
import socket
import subprocess
import sys
import unittest

from lab_log_pump import LabLogPump


class LogPumpTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux firmware-lab socket backpressure")
    def test_log_and_pipe_pressure_drains_after_capture_is_full(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        child = subprocess.Popen([sys.executable, "-c", """
import os, socket, sys
s = socket.socket(fileno=int(sys.argv[1]))
for _ in range(256):
    s.send(b'L' * 1024)
os.write(1, b'O' * 131072)
os.write(2, b'E' * 131072)
""", str(sender.fileno())], pass_fds=(sender.fileno(),),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Demonstrate the old no-drain wait cannot finish this workload.
            with self.assertRaises(subprocess.TimeoutExpired):
                child.wait(timeout=0.15)
            pump = LabLogPump(receiver)
            result = pump.wait(child, 5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(pump.retained_bytes, 65536)
            self.assertEqual(pump.omitted_messages, 192)
            self.assertEqual(len(result.stdout), 65536)
            self.assertEqual(len(result.stderr), 65536)
            self.assertEqual(result.omitted_bytes, {"stdout": 65536, "stderr": 65536})
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()
            receiver.close()
            sender.close()

    def test_timeout_retains_child_for_owner_cleanup(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                LabLogPump(receiver).wait(child, 0.05)
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()
            receiver.close()
            sender.close()


if __name__ == "__main__":
    unittest.main()
