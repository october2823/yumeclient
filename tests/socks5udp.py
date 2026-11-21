"""A small SOCKS5 proxy for the tests: CONNECT and UDP ASSOCIATE (RFC 1928), optional
username/password (RFC 1929). Records what clients asked for in ``log``."""
from __future__ import annotations

import socket
import struct
import threading


def _recvn(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def _read_addr(conn: socket.socket) -> tuple[str, int]:
    atyp = _recvn(conn, 1)[0]
    if atyp == 1:
        host = socket.inet_ntoa(_recvn(conn, 4))
    elif atyp == 3:
        host = _recvn(conn, _recvn(conn, 1)[0]).decode()
    else:
        host = socket.inet_ntop(socket.AF_INET6, _recvn(conn, 16))
    return host, struct.unpack(">H", _recvn(conn, 2))[0]


def _udp_header(host: str, port: int) -> bytes:
    return b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port)


class Socks5:
    def __init__(self, auth: tuple[str, str] | None = None):
        self.auth = auth
        self.log: list[tuple] = []
        self.datagrams = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.url = f"socks5://{auth[0]}:{auth[1]}@127.0.0.1:{self.port}" if auth else f"socks5://127.0.0.1:{self.port}"
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self.sock.close()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            ver, n = _recvn(conn, 2)
            methods = _recvn(conn, n)
            if self.auth:
                if 2 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x02")
                _recvn(conn, 1)
                user = _recvn(conn, _recvn(conn, 1)[0]).decode()
                password = _recvn(conn, _recvn(conn, 1)[0]).decode()
                ok = (user, password) == self.auth
                conn.sendall(b"\x01\x00" if ok else b"\x01\x01")
                if not ok:
                    return
            else:
                conn.sendall(b"\x05\x00")
            _, cmd, _ = _recvn(conn, 3)
            host, port = _read_addr(conn)
            if cmd == 1:
                self.log.append(("connect", host, port))
                upstream = socket.create_connection((host, port), timeout=5)
                upstream.settimeout(None)
                conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))
                self._relay_tcp(conn, upstream)
            elif cmd == 3:
                self.log.append(("udp_associate", host, port))
                self._relay_udp(conn)
            else:
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        except (OSError, ConnectionError, ValueError):
            pass
        finally:
            conn.close()

    @staticmethod
    def _relay_tcp(a: socket.socket, b: socket.socket) -> None:
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        threading.Thread(target=pump, args=(b, a), daemon=True).start()
        pump(a, b)
        b.close()

    def _relay_udp(self, control: socket.socket) -> None:
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        relay_port = relay.getsockname()[1]
        control.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", relay_port))
        client: tuple[str, int] | None = None
        stop = threading.Event()

        def pump():
            nonlocal client
            relay.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = relay.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if data[:3] == b"\x00\x00\x00" and data[3] == 1 and (client is None or addr == client):
                    client = addr
                    target = (socket.inet_ntoa(data[4:8]), struct.unpack(">H", data[8:10])[0])
                    self.datagrams += 1
                    self.log.append(("udp", *target)) if ("udp", *target) not in self.log else None
                    relay.sendto(data[10:], target)
                elif client is not None:
                    relay.sendto(_udp_header(*addr) + data, client)

        worker = threading.Thread(target=pump, daemon=True)
        worker.start()
        try:
            while control.recv(1024):  # the association lives as long as the control connection
                pass
        except OSError:
            pass
        finally:
            stop.set()
            worker.join(1)
            relay.close()
