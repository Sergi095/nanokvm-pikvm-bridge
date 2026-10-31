import asyncio
import base64
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote

from tornado import httpclient, httpserver, iostream, netutil, testing, web, websocket

import bridge

USER = "bridge-test"
PASSWORD = "test-password-with-a-period."
JPEG = (Path(__file__).parent / "frame.jpg").read_bytes()


from test_bridge import FakeNano, FakeInput, AUTH

class Client:
    """Independent RFB wire client: assertions follow the published protocol."""
    def __init__(self, port):
        self.port = port
        self.stream = iostream.IOStream(socket.socket())

    async def connect(self, username=USER, password=PASSWORD, credentials=True, tls=None):
        await self.stream.connect(('127.0.0.1', self.port))
        assert await self.stream.read_bytes(12) == b'RFB 003.008\n'
        await self.stream.write(b'RFB 003.008\n')
        assert await self.stream.read_bytes(2) == b'\x01\x13'
        await self.stream.write(b'\x13')
        assert await self.stream.read_bytes(2) == b'\x00\x02'
        await self.stream.write(b'\x00\x02')
        assert await self.stream.read_bytes(6) == b'\x00\x01\x00\x00\x01\x06'
        await self.stream.write(b'\x00\x00\x01\x06')
        assert await self.stream.read_bytes(1) == b'\x01'
        self.stream = await self.stream.start_tls(False, ssl_options=tls or ssl._create_unverified_context())
        if not credentials:
            return
        user, pw = username.encode(), password.encode()
        await self.stream.write(struct.pack('>II', len(user), len(pw)) + user + pw)
        result = int.from_bytes(await self.stream.read_bytes(4), 'big')
        if result:
            length = int.from_bytes(await self.stream.read_bytes(4), 'big')
            return (await self.stream.read_bytes(length)).decode()
        await self.stream.write(b'\x01')
        header = await self.stream.read_bytes(24)
        self.width, self.height = struct.unpack('>HH', header[:4])
        assert header[4:20] == bytes.fromhex('2018000100ff00ff00ff100800000000')
        self.name = await self.stream.read_bytes(int.from_bytes(header[20:24], 'big'))
        await self.encodings([7, -26, -223])
        return None

    async def encodings(self, encodings):
        await self.stream.write(struct.pack('>BBH', 2, 0, len(encodings))
                                + struct.pack('>' + 'i' * len(encodings), *encodings))

    async def frame(self, incremental=False):
        await self.stream.write(struct.pack('>BBHHHH', 3, incremental, 0, 0, self.width, self.height))
        assert await self.stream.read_bytes(4) == b'\x00\x00\x00\x01'
        x, y, width, height, encoding = struct.unpack('>HHHHi', await self.stream.read_bytes(12))
        assert (x, y) == (0, 0)
        if encoding == -223:
            self.width, self.height = width, height
            return None
        assert encoding == 7
        assert (width, height) == (self.width, self.height)
        assert await self.stream.read_bytes(1) == b'\x90'
        first = (await self.stream.read_bytes(1))[0]
        length = first & 127
        if first & 128:
            second = (await self.stream.read_bytes(1))[0]
            length |= (second & 127) << 7
            if second & 128:
                length |= (await self.stream.read_bytes(1))[0] << 14
        return await self.stream.read_bytes(length)

    async def key(self, sym, down=True):
        await self.stream.write(struct.pack('>BB2xI', 4, down, sym))

    async def pointer(self, mask, x, y):
        await self.stream.write(struct.pack('>BBHH', 5, mask, x, y))

    def close(self):
        if self.stream.socket is not None:
            self.stream.close()


class BridgeTests(testing.AsyncTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = cls.temp.name + '/cert.pem'
        cls.key = cls.temp.name + '/key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', cls.key, '-out', cls.cert, '-days', '1', '-subj', '/CN=localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        super().setUp()
        self.state = dict(logins=0, power=False, pulses=[], reports=[], connections=0,
                          revoked=False, cookie_auth=True, jpeg=JPEG, end_video=False, hdmi=True)
        upstream = web.Application([
            (r'/api/ws', FakeInput, {'state': self.state}),
            (r'/api/(.*)', FakeNano, {'state': self.state}),
        ])
        sock = netutil.bind_sockets(0, '127.0.0.1')[0]
        port = sock.getsockname()[1]
        self.upstream = httpserver.HTTPServer(upstream)
        self.upstream.add_socket(sock)
        self.nano = bridge.NanoKVM(f'http://127.0.0.1:{port}', None)
        tls = bridge.server_tls(self.cert, self.key)
        self.server = bridge.VNCServer(self.nano, tls, max_fps=60)
        sock = netutil.bind_sockets(0, '127.0.0.1')[0]
        self.port = sock.getsockname()[1]
        self.server.add_socket(sock)
        sock = netutil.bind_sockets(0, '127.0.0.1')[0]
        self.api_port = sock.getsockname()[1]
        self.api = httpserver.HTTPServer(bridge.application(self.nano))
        self.api.add_socket(sock)
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.io_loop.run_sync(self.server.shutdown)
        if self.nano.controller:
            self.io_loop.run_sync(self.nano.controller.close)
        self.api.stop()
        self.io_loop.run_sync(self.api.close_all_connections)
        self.state['end_video'] = True
        self.upstream.stop()
        self.io_loop.run_sync(self.upstream.close_all_connections)
        self.nano.http.close()
        super().tearDown()

    async def client(self, **kwargs):
        client = Client(self.port)
        self.clients.append(client)
        result = await client.connect(**kwargs)
        return client, result

    async def wait_for(self, predicate):
        async def poll():
            while not predicate():
                await asyncio.sleep(0.005)
        await asyncio.wait_for(poll(), 2)

    @testing.gen_test
    async def test_tls_auth_and_jpeg_pass_through(self):
        client, error = await self.client()
        self.assertIsNone(error)
        self.assertEqual((client.width, client.height), (16, 12))
        self.assertEqual(client.name, b'NanoKVM bridge')
        for _ in range(3):
            self.assertEqual(await client.frame(True), JPEG)
        client.close()
        await self.wait_for(lambda: self.nano.vnc_client is None)
        self.assertEqual(self.state['reports'], [])
        self.assertEqual(self.state['pulses'], [])

    @testing.gen_test
    async def test_wrong_password_and_disabled_auth(self):
        client, error = await self.client(password=PASSWORD[:-1])
        self.assertEqual(error, 'NanoKVM login failed')
        self.assertEqual(self.state['connections'], 0)
        client.close()
        self.state['cookie_auth'] = False
        _, error = await self.client()
        self.assertEqual(error, 'NanoKVM login failed')
        self.assertIsNone(self.nano.vnc_client)

    @testing.gen_test
    async def test_second_controller_is_rejected(self):
        first, error = await self.client()
        self.assertIsNone(error)
        second, error = await self.client()
        self.assertEqual(error, 'Another bridge input client is connected')
        second.close()
        self.assertEqual(self.state['connections'], 1)
        self.assertIsNotNone(self.nano.vnc_client)
        self.assertEqual(await first.frame(), JPEG)

    @testing.gen_test
    async def test_vnc_and_http_video_coexist_but_input_is_exclusive(self):
        client, _ = await self.client()
        http = httpclient.AsyncHTTPClient()
        url = f'http://127.0.0.1:{self.api_port}'
        response = await http.fetch(httpclient.HTTPRequest(url + '/streamer/snapshot', headers=AUTH))
        self.assertEqual(response.body, JPEG)
        response = await http.fetch(httpclient.HTTPRequest(
            url + '/api/hid/events/send_key?key=KeyA', headers=AUTH, method='POST', body=''), raise_error=False)
        self.assertEqual(response.code, 409)
        self.assertEqual(self.state['reports'], [])
        self.assertEqual(await client.frame(), JPEG)
        client.close()
        await self.wait_for(lambda: self.nano.vnc_client is None)
        response = await http.fetch(httpclient.HTTPRequest(
            url + '/api/hid/events/send_key?key=KeyA', headers=AUTH, method='POST', body=''))
        self.assertEqual(response.code, 200)

    @testing.gen_test
    async def test_http_controller_blocks_vnc_without_interrupting_input(self):
        session = await self.nano.login(USER, PASSWORD)
        channel = await bridge.controller(self.nano, session)
        _, error = await self.client()
        self.assertEqual(error, 'Another bridge input client is connected')
        self.assertIs(self.nano.controller, channel)
        await channel.send('key', {'key': 'KeyA', 'state': True})
        await self.wait_for(lambda: len(self.state['reports']) == 1)
        await channel.close()
        client, error = await self.client()
        self.assertIsNone(error)
        self.assertEqual(await client.frame(), JPEG)

    @testing.gen_test
    async def test_revocation_closes_live_vnc_and_releases_keys(self):
        async def fast_keepalive(connection):
            while True:
                await asyncio.sleep(0.02)
                await connection.check_session()
        with patch.object(bridge.VNCConnection, 'keepalive', fast_keepalive):
            client, _ = await self.client()
            await client.key(ord('z'))
            await self.wait_for(lambda: any(r[0] == 1 for r in self.state['reports']))
            self.state['revoked'] = True
            with self.assertRaises(iostream.StreamClosedError):
                await client.stream.read_bytes(1)
            await self.wait_for(lambda: self.nano.vnc_client is None)
            self.assertEqual(self.state['reports'][-1], bytes([1] + [0] * 8))

    @testing.gen_test
    async def test_video_limit_shared_between_protocols(self):
        # Represent two existing HTTP viewers; VNC must not open a third capture.
        viewers = {object(), object()}
        self.nano.streams.update(viewers)
        with self.assertRaises(iostream.StreamClosedError):
            await self.client()
        self.assertIsNone(self.nano.vnc_client)
        self.assertEqual(self.nano.streams, viewers)
        self.nano.streams.clear()

    @testing.gen_test
    async def test_revoked_session_cannot_reconnect(self):
        first, _ = await self.client()
        first.close()
        await self.wait_for(lambda: self.nano.vnc_client is None)
        self.state['revoked'] = True
        _, error = await self.client()
        self.assertEqual(error, 'NanoKVM login failed')

    @testing.gen_test
    async def test_keyboard_mouse_and_disconnect_release(self):
        client, _ = await self.client()
        await client.key(0xffe3)  # Left Control
        await client.key(ord('a'))
        await client.pointer(1, 15, 11)
        await client.pointer(4 | 8, 0, 0)  # Right click and wheel up
        await self.wait_for(lambda: len(self.state['reports']) == 4)
        self.assertEqual(self.state['reports'], [
            bytes([1, 1, 0, 0, 0, 0, 0, 0, 0]),
            bytes([1, 1, 0, 4, 0, 0, 0, 0, 0]),
            bytes([2, 1, 255, 127, 255, 127, 0]),
            bytes([2, 2, 0, 0, 0, 0, 1]),
        ])
        client.close()
        await self.wait_for(lambda: self.nano.vnc_client is None and self.state['connections'] == 0)
        self.assertEqual(self.state['reports'][-2:], [bytes([1] + [0] * 8), bytes([2] + [0] * 6)])

    @testing.gen_test
    async def test_clipboard_and_unsupported_keys_do_not_type(self):
        client, _ = await self.client()
        await client.key(0x010020ac)  # Unsupported Unicode euro sign
        await client.stream.write(b'\x06\x00\x00\x00\x00\x00\x00\x05hello')
        self.assertEqual(await client.frame(), JPEG)
        self.assertEqual(self.state['reports'], [])

    @testing.gen_test
    async def test_backend_disconnect_closes_client(self):
        client, _ = await self.client()
        self.state['backend'].close()
        with self.assertRaises(iostream.StreamClosedError):
            await client.stream.read_bytes(1)
        await self.wait_for(lambda: self.nano.vnc_client is None)

    @testing.gen_test
    async def test_invalid_encodings_and_pixel_format_close(self):
        client, _ = await self.client()
        await client.encodings([0])
        with self.assertRaises(iostream.StreamClosedError):
            await client.stream.read_bytes(1)
        await self.wait_for(lambda: self.nano.vnc_client is None)
        client, _ = await self.client()
        await client.stream.write(b'\x00\x00\x00\x00' + bytes([8, 8, 0, 1]) + bytes(12))
        with self.assertRaises(iostream.StreamClosedError):
            await client.stream.read_bytes(1)

    @testing.gen_test
    async def test_credential_length_is_bounded_before_read(self):
        client, _ = await self.client(credentials=False)
        await client.stream.write(struct.pack('>II', 0xffffffff, 0xffffffff))
        with self.assertRaises(iostream.StreamClosedError):
            await client.stream.read_bytes(1)
        self.assertEqual(self.state['logins'], 0)

    @testing.gen_test
    async def test_tls_rejection_releases_connection_without_authentication(self):
        tls = ssl.create_default_context()
        tls.check_hostname = False
        with self.assertRaises((ssl.SSLError, iostream.StreamClosedError)):
            await self.client(tls=tls)
        await self.wait_for(lambda: not self.server.clients)
        self.assertEqual(self.state['logins'], 0)
        self.assertIsNone(self.nano.vnc_client)

    @testing.gen_test
    async def test_latest_frame_and_resize(self):
        client, _ = await self.client()
        self.assertEqual(await client.frame(), JPEG)
        # A comment segment changes the payload while keeping the same image.
        updated = JPEG[:2] + b'\xff\xfe\x00\x05new' + JPEG[2:]
        self.state['jpeg'] = updated
        await self.wait_for(lambda: self.nano.vnc_client.frame == updated)
        self.assertEqual(await client.frame(True), updated)
        resized = bytearray(updated)
        sof = resized.index(b'\xff\xc0')
        resized[sof + 7:sof + 9] = b'\x00\x08'
        self.state['jpeg'] = bytes(resized)
        await self.wait_for(lambda: self.nano.vnc_client.frame_size == (8, 12))
        self.assertIsNone(await client.frame(True))
        self.assertEqual((client.width, client.height), (8, 12))
        self.assertEqual(await client.frame(), bytes(resized))

    @testing.gen_test
    async def test_shutdown_releases_held_keys(self):
        client, _ = await self.client()
        await client.key(ord('z'))
        await self.wait_for(lambda: len(self.state['reports']) == 1)
        await self.server.shutdown()
        await self.wait_for(lambda: self.state['connections'] == 0)
        self.assertEqual(self.state['reports'][-1], bytes([1] + [0] * 8))
        self.assertIsNone(self.nano.vnc_client)


class InputStateTests(unittest.TestCase):
    def test_shifted_symbols_preserve_explicit_modifiers(self):
        state = bridge.VNCInputState()
        state.key(0xffe3, True)
        self.assertEqual(state.key(ord('!'), True), bytes([1, 3, 0, 30, 0, 0, 0, 0, 0]))
        self.assertEqual(state.key(ord('!'), False), bytes([1, 1, 0, 0, 0, 0, 0, 0, 0]))
        state.key(0xffe2, True)
        state.key(ord('A'), True)
        self.assertEqual(state.key(ord('A'), False)[1], 33)

    def test_rollover_and_idle_release(self):
        state = bridge.VNCInputState()
        self.assertEqual(state.release(), [])
        for letter in 'abcdef':
            state.key(ord(letter), True)
        self.assertIsNone(state.key(ord('g'), True))
        state.key(ord('a'), False)
        self.assertIsNotNone(state.key(ord('g'), True))
        self.assertEqual(state.release(), [bytes([1] + [0] * 8)])

    def test_mouse_buttons_coordinates_and_wheel_edges(self):
        state = bridge.VNCInputState()
        self.assertEqual(state.pointer(2, 999, 999, 16, 12), bytes([2, 4, 255, 127, 255, 127, 0]))
        self.assertEqual(state.pointer(16, 0, 0, 16, 12)[-1], 255)
        self.assertEqual(state.pointer(16, 0, 0, 16, 12)[-1], 0)
        self.assertEqual(state.pointer(8, 0, 0, 16, 12)[-1], 1)


class FrameTests(unittest.TestCase):
    def test_size_and_corrupt_jpegs(self):
        self.assertEqual(bridge.jpeg_size(JPEG), (16, 12))
        for bad in (b'', JPEG[:-2], b'\xff\xd8\xff\xc0\x00\x00\xff\xd9'):
            with self.assertRaises(ValueError):
                bridge.jpeg_size(bad)

    def test_compact_length_boundaries(self):
        for value, encoded in [(0, b'\x00'), (127, b'\x7f'), (128, b'\x80\x01'),
                               (16383, b'\xff\x7f'), (16384, b'\x80\x80\x01'),
                               (4194303, b'\xff\xff\xff')]:
            self.assertEqual(bridge.compact_length(value), encoded)
        with self.assertRaises(ValueError):
            bridge.compact_length(4194304)


if __name__ == '__main__':
    unittest.main()
