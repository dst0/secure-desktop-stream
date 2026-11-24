#!/usr/bin/env python3
"""UDP-over-TCP relay for throwaway stream tests through an SSH tunnel.

Sunshine streams video/audio/control over UDP, which `ssh -L` cannot carry. For a functional
test without opening host firewall ports, run:

  host (via ssh):  udp_relay.py host --listen 127.0.0.1:47001 --ports 47998,47999,48000
  mac:             ssh -N -L 47001:127.0.0.1:47001 -L 47984:127.0.0.1:47984 \
                       -L 47989:127.0.0.1:47989 -L 48010:127.0.0.1:48010 <host>
                   udp_relay.py client --connect 127.0.0.1:47001 --ports 47998,47999,48000

then point Moonlight at 127.0.0.1. All UDP datagrams are multiplexed over one TCP stream with
framing: u8 port index, u16 big-endian length, payload. Latency is not representative of a
real LAN stream; use it for functional checks only.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import struct
import sys

HDR = struct.Struct("!BH")
MAX_DATAGRAM = 65507
MAX_TCP_WRITE_BUFFER = 4 * 1024 * 1024

log = logging.getLogger("udp_relay")


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_loopback(host: str, label: str, allow_non_loopback: bool = False) -> None:
    if not allow_non_loopback and not is_loopback_host(host):
        raise ValueError(f"{label} address {host!r} is not loopback (pass --allow-non-loopback to override)")


def parse_hostport(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"expected host:port, got {value!r}")
    return host, int(port)


def parse_ports(value: str) -> list[int]:
    ports = []
    for item in value.split(","):
        item = item.strip()
        if not item.isdigit() or not 0 < int(item) < 65536:
            raise argparse.ArgumentTypeError(f"bad port {item!r}")
        ports.append(int(item))
    if not ports or len(ports) > 255 or len(set(ports)) != len(ports):
        raise argparse.ArgumentTypeError("need 1-255 distinct ports")
    return ports


def encode_frame(index: int, payload: bytes) -> bytes:
    if not 0 <= index <= 255:
        raise ValueError("port index out of range")
    if len(payload) > MAX_DATAGRAM:
        raise ValueError("datagram too large")
    return HDR.pack(index, len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    hdr = await reader.readexactly(HDR.size)
    index, length = HDR.unpack(hdr)
    if length > MAX_DATAGRAM:
        raise ValueError(f"frame length {length} exceeds MAX_DATAGRAM ({MAX_DATAGRAM})")
    payload = await reader.readexactly(length) if length else b""
    return index, payload


def _write_frame_bounded(writer: asyncio.StreamWriter | None, index: int, data: bytes) -> bool:
    if writer is None or writer.is_closing():
        return False
    if len(data) > MAX_DATAGRAM:
        log.warning("dropping oversized datagram (%d bytes) on port index %d", len(data), index)
        return False
    transport = getattr(writer, "transport", None)
    if transport is not None and transport.get_write_buffer_size() > MAX_TCP_WRITE_BUFFER:
        log.warning("dropping datagram: tcp write buffer exceeds %d bytes", MAX_TCP_WRITE_BUFFER)
        return False
    writer.write(encode_frame(index, data))
    return True


class _Datagram(asyncio.DatagramProtocol):
    def __init__(self, on_datagram):
        self.on_datagram = on_datagram
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.on_datagram(data, addr)


class ClientSide:
    """Listens on local UDP ports (where Moonlight sends) and forwards over TCP."""

    def __init__(self, ports: list[int], bind: str = "127.0.0.1", allow_non_loopback: bool = False):
        require_loopback(bind, "bind", allow_non_loopback)
        self.ports = ports
        self.bind = bind
        self.peers: dict[int, tuple] = {}
        self.endpoints: dict[int, _Datagram] = {}
        self.writer: asyncio.StreamWriter | None = None

    async def open_udp(self):
        loop = asyncio.get_running_loop()
        for i, port in enumerate(self.ports):
            def handler(data, addr, i=i):
                self.peers[i] = addr
                _write_frame_bounded(self.writer, i, data)
            _, proto = await loop.create_datagram_endpoint(lambda h=handler: _Datagram(h), local_addr=(self.bind, port))
            self.endpoints[i] = proto

    async def run(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.writer = writer
        try:
            while True:
                index, payload = await read_frame(reader)
                peer = self.peers.get(index)
                ep = self.endpoints.get(index)
                if peer is not None and ep is not None and ep.transport is not None:
                    ep.transport.sendto(payload, peer)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            log.info("tcp connection closed")
        except ValueError as e:
            log.warning("closing tcp connection on invalid frame: %s", e)
            writer.close()

    def close(self):
        for ep in self.endpoints.values():
            if ep.transport is not None:
                ep.transport.close()


class HostSide:
    """Accepts the TCP stream and talks UDP to the local service ports."""

    def __init__(self, ports: list[int], target: str = "127.0.0.1", allow_non_loopback: bool = False):
        require_loopback(target, "target", allow_non_loopback)
        self.ports = ports
        self.target = target
        self._active_client: asyncio.StreamWriter | None = None

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self._active_client is not None:
            log.warning("rejecting extra tcp client while one session is active")
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return
        self._active_client = writer
        loop = asyncio.get_running_loop()
        endpoints: dict[int, _Datagram] = {}
        try:
            expected_hosts: dict[int, str] = {}
            for i, port in enumerate(self.ports):
                def handler(data, addr, i=i, port=port):
                    if addr is None or len(addr) < 2 or addr[0] != expected_hosts[i] or addr[1] != port:
                        return
                    _write_frame_bounded(writer, i, data)
                _, proto = await loop.create_datagram_endpoint(lambda h=handler: _Datagram(h), local_addr=(self.target, 0))
                sockname = proto.transport.get_extra_info("sockname") if proto.transport is not None else None
                expected_hosts[i] = sockname[0] if sockname else self.target
                endpoints[i] = proto
            while True:
                index, payload = await read_frame(reader)
                if index < len(self.ports) and endpoints[index].transport is not None:
                    endpoints[index].transport.sendto(payload, (self.target, self.ports[index]))
        except (asyncio.IncompleteReadError, ConnectionResetError):
            log.info("tcp connection closed")
        except ValueError as e:
            log.warning("closing tcp connection on invalid frame: %s", e)
        finally:
            for ep in endpoints.values():
                if ep.transport is not None:
                    ep.transport.close()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            if self._active_client is writer:
                self._active_client = None


def validate_args(args) -> None:
    if args.mode == "host":
        require_loopback(args.listen[0], "listen", args.allow_non_loopback)
    else:
        require_loopback(args.connect[0], "connect", args.allow_non_loopback)


async def main_async(args) -> int:
    validate_args(args)
    if args.mode == "host":
        host, port = args.listen
        side = HostSide(args.ports, allow_non_loopback=args.allow_non_loopback)
        server = await asyncio.start_server(side.handle, host, port)
        log.info("host relay listening on %s:%d for UDP ports %s", host, port, args.ports)
        async with server:
            await server.serve_forever()
    else:
        side = ClientSide(args.ports, allow_non_loopback=args.allow_non_loopback)
        await side.open_udp()
        while True:
            try:
                reader, writer = await asyncio.open_connection(*args.connect)
            except OSError as e:
                log.warning("connect failed: %s; retrying", e)
                await asyncio.sleep(1)
                continue
            log.info("connected to %s:%d", *args.connect)
            await side.run(reader, writer)
            await asyncio.sleep(0.5)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--allow-non-loopback", action="store_true", default=False,
                   help="Allow binding or connecting to non-loopback addresses")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="mode", required=True)
    h = sub.add_parser("host")
    h.add_argument("--listen", type=parse_hostport, required=True)
    h.add_argument("--ports", type=parse_ports, required=True)
    h.add_argument("--allow-non-loopback", action="store_true", default=argparse.SUPPRESS)
    c = sub.add_parser("client")
    c.add_argument("--connect", type=parse_hostport, required=True)
    c.add_argument("--ports", type=parse_ports, required=True)
    c.add_argument("--allow-non-loopback", action="store_true", default=argparse.SUPPRESS)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        validate_args(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(message)s")
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
