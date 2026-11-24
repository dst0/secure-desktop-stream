"""Tests for tools/udp_relay.py (run: python3 -I -m pytest tests/test_udp_relay.py or python3 -I tests/test_udp_relay.py)."""
import asyncio
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import udp_relay  # noqa: E402


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Echo(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.last_addr = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.last_addr = addr
        self.transport.sendto(b"echo:" + data, addr)


class FramingTests(unittest.TestCase):
    def test_encode_roundtrip(self):
        async def go():
            r = asyncio.StreamReader()
            r.feed_data(udp_relay.encode_frame(3, b"abc") + udp_relay.encode_frame(0, b""))
            r.feed_eof()
            self.assertEqual(await udp_relay.read_frame(r), (3, b"abc"))
            self.assertEqual(await udp_relay.read_frame(r), (0, b""))
            with self.assertRaises(asyncio.IncompleteReadError):
                await udp_relay.read_frame(r)
        asyncio.run(go())

    def test_encode_limits(self):
        with self.assertRaises(ValueError):
            udp_relay.encode_frame(256, b"x")
        with self.assertRaises(ValueError):
            udp_relay.encode_frame(0, b"x" * (udp_relay.MAX_DATAGRAM + 1))

    def test_read_frame_rejects_oversized_length(self):
        async def go():
            r = asyncio.StreamReader()
            r.feed_data(udp_relay.HDR.pack(0, udp_relay.MAX_DATAGRAM + 1) + b"x" * 16)
            r.feed_eof()
            with self.assertRaisesRegex(ValueError, "MAX_DATAGRAM"):
                await udp_relay.read_frame(r)
        asyncio.run(go())

    def test_parsers(self):
        self.assertEqual(udp_relay.parse_hostport("127.0.0.1:47001"), ("127.0.0.1", 47001))
        self.assertEqual(udp_relay.parse_hostport("[::1]:47001"), ("::1", 47001))
        self.assertEqual(udp_relay.parse_ports("1,2,3"), [1, 2, 3])
        for bad in ["x", "1,1", "0", "70000", ""]:
            with self.assertRaises(Exception):
                udp_relay.parse_ports(bad)
        for bad in ["nohost", ":1", "h:0", "h:x"]:
            with self.assertRaises(Exception):
                udp_relay.parse_hostport(bad)

    def test_loopback_enforced_by_default_and_override(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            udp_relay.HostSide([47998], target="0.0.0.0")
        with self.assertRaisesRegex(ValueError, "loopback"):
            udp_relay.ClientSide([47998], bind="192.0.2.10")
        udp_relay.HostSide([47998], target="192.0.2.10", allow_non_loopback=True)
        udp_relay.ClientSide([47998], bind="192.0.2.10", allow_non_loopback=True)
        self.assertEqual(udp_relay.main(["host", "--listen", "0.0.0.0:47001", "--ports", "47998"]), 2)
        self.assertEqual(udp_relay.main(["client", "--connect", "192.0.2.10:47001", "--ports", "47998"]), 2)
        self.assertTrue(
            udp_relay.build_parser().parse_args(
                ["host", "--listen", "0.0.0.0:47001", "--ports", "47998", "--allow-non-loopback"]
            ).allow_non_loopback
        )
        self.assertTrue(
            udp_relay.build_parser().parse_args(
                ["--allow-non-loopback", "client", "--connect", "192.0.2.10:47001", "--ports", "47998"]
            ).allow_non_loopback
        )

    def test_write_buffer_drops_datagrams_over_4mib(self):
        class FakeTransport:
            def __init__(self, size):
                self.size = size

            def get_write_buffer_size(self):
                return self.size

        class FakeWriter:
            def __init__(self, size):
                self.transport = FakeTransport(size)
                self.written = []

            def is_closing(self):
                return False

            def write(self, data):
                self.written.append(data)

        ok_writer = FakeWriter(udp_relay.MAX_TCP_WRITE_BUFFER)
        self.assertTrue(udp_relay._write_frame_bounded(ok_writer, 0, b"hi"))
        self.assertEqual(len(ok_writer.written), 1)

        full_writer = FakeWriter(udp_relay.MAX_TCP_WRITE_BUFFER + 1)
        self.assertFalse(udp_relay._write_frame_bounded(full_writer, 0, b"hi"))
        self.assertEqual(full_writer.written, [])


class EndToEndTests(unittest.TestCase):
    def test_datagrams_round_trip_through_tcp(self):
        async def go():
            loop = asyncio.get_running_loop()
            service_ports = [free_udp_port(), free_udp_port()]
            services = [await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", p)) for p in service_ports]
            host = udp_relay.HostSide(service_ports)
            server = await asyncio.start_server(host.handle, "127.0.0.1", 0)
            tcp_port = server.sockets[0].getsockname()[1]
            client_ports = [free_udp_port(), free_udp_port()]
            client = udp_relay.ClientSide(client_ports)
            await client.open_udp()
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
            run = asyncio.create_task(client.run(reader, writer))

            got = asyncio.Queue()

            class App(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    got.put_nowait((addr[1], data))

            app_t, _ = await loop.create_datagram_endpoint(App, local_addr=("127.0.0.1", 0))
            for i, cp in enumerate(client_ports):
                for n in range(5):
                    app_t.sendto(f"p{i}-{n}".encode(), ("127.0.0.1", cp))
            results = [await asyncio.wait_for(got.get(), 5) for _ in range(10)]
            by_port = {}
            for src, data in results:
                by_port.setdefault(src, []).append(data)
            self.assertEqual(sorted(by_port), sorted(client_ports))
            for i, cp in enumerate(client_ports):
                self.assertEqual(sorted(by_port[cp]), sorted(f"echo:p{i}-{n}".encode() for n in range(5)))
            # A large datagram survives intact.
            big = os.urandom(8000)  # macOS loopback caps UDP datagrams at net.inet.udp.maxdgram (9216)
            app_t.sendto(big, ("127.0.0.1", client_ports[0]))
            src, data = await asyncio.wait_for(got.get(), 5)
            self.assertEqual(data, b"echo:" + big)

            run.cancel()
            writer.close()
            client.close()
            app_t.close()
            for t, _ in services:
                t.close()
            server.close()
            await server.wait_closed()
        asyncio.run(go())

    def test_host_side_limits_to_one_active_client(self):
        async def go():
            loop = asyncio.get_running_loop()
            service_port = free_udp_port()
            echo_t, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", service_port))
            host = udp_relay.HostSide([service_port])
            server = await asyncio.start_server(host.handle, "127.0.0.1", 0)
            tcp_port = server.sockets[0].getsockname()[1]

            r1, w1 = await asyncio.open_connection("127.0.0.1", tcp_port)
            w1.write(udp_relay.encode_frame(0, b"one"))
            await w1.drain()
            self.assertEqual(await asyncio.wait_for(udp_relay.read_frame(r1), 5), (0, b"echo:one"))

            r2, w2 = await asyncio.open_connection("127.0.0.1", tcp_port)
            self.assertEqual(await asyncio.wait_for(r2.read(1), 5), b"")
            w2.close()

            w1.close()
            await w1.wait_closed()
            await asyncio.sleep(0.05)

            r3, w3 = await asyncio.open_connection("127.0.0.1", tcp_port)
            w3.write(udp_relay.encode_frame(0, b"three"))
            await w3.drain()
            self.assertEqual(await asyncio.wait_for(udp_relay.read_frame(r3), 5), (0, b"echo:three"))
            w3.close()
            await w3.wait_closed()

            echo_t.close()
            server.close()
            await server.wait_closed()
        asyncio.run(go())

    def test_host_side_verifies_udp_source_address(self):
        async def go():
            loop = asyncio.get_running_loop()
            service_port = free_udp_port()
            echo_t, echo = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", service_port))
            host = udp_relay.HostSide([service_port])
            server = await asyncio.start_server(host.handle, "127.0.0.1", 0)
            tcp_port = server.sockets[0].getsockname()[1]

            r, w = await asyncio.open_connection("127.0.0.1", tcp_port)
            w.write(udp_relay.encode_frame(0, b"probe"))
            await w.drain()
            self.assertEqual(await asyncio.wait_for(udp_relay.read_frame(r), 5), (0, b"echo:probe"))

            rogue_t, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0))
            rogue_t.sendto(b"spoofed", echo.last_addr)
            echo.transport.sendto(b"legit", echo.last_addr)
            self.assertEqual(await asyncio.wait_for(udp_relay.read_frame(r), 5), (0, b"legit"))

            rogue_t.close()
            w.close()
            await w.wait_closed()
            echo_t.close()
            server.close()
            await server.wait_closed()
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
