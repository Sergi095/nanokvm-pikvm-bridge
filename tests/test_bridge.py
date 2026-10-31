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
from urllib.parse import unquote, urlencode

from tornado import httpclient, httpserver, iostream, netutil, testing, web, websocket

import bridge

USER = "bridge-test"
PASSWORD = "test-password-with-a-period."
JPEG = (Path(__file__).parent / "frame.jpg").read_bytes()


class FakeNano(web.RequestHandler):
    def initialize(self, state):
        self.state = state

    def prepare(self):
        if self.request.path != "/api/auth/login":
            if self.get_cookie("nano-kvm-token") != "test-session" or self.state["revoked"]:
                raise web.HTTPError(401)

    def ok(self, data=None):
        self.finish({"code": 0, "msg": "success", "data": data})

    async def post(self, path):
        data = json.loads(self.request.body)
        if path == "auth/login":
            self.state["logins"] += 1
            # Independently decrypt through OpenSSL, including its salted header.
            encoded = unquote(data["password"])
            decoded = subprocess.run([
                "openssl", "enc", "-d", "-aes-256-cbc", "-md", "md5",
                "-pass", "pass:nanokvm-sipeed-2024",
            ], input=base64.b64decode(encoded), capture_output=True, check=True).stdout
            if data["username"] != USER or decoded.decode() != PASSWORD:
                self.finish({"code": -2, "msg": "invalid credentials"})
                return
            if self.state["cookie_auth"]:
                self.set_cookie("nano-kvm-token", "test-session", httponly=True)
            self.ok()
        elif path == 'hid/paste':
            self.state['paste'].append(data)
            self.ok()
        elif path == 'vm/screen':
            if self.state['screen_failure']:
                self.finish({'code': -2, 'msg': 'update failed'})
                return
            self.state['screen'].append(data)
            self.ok()
        elif path == 'vm/hdmi/reset':
            self.state['capture_resets'] += 1
            self.ok()
        elif path == "vm/gpio":
            self.state["pulses"].append(data)
            if data["type"] == "power":
                self.state["power"] = not self.state["power"]
            self.ok()
        else:
            raise web.HTTPError(404)

    async def get(self, path):
        if path == "auth/account":
            self.ok({"username": USER, "role": "admin"})
        elif path == 'vm/hdmi':
            self.ok({'enabled': True, 'signal': self.state['hdmi']})
        elif path == "vm/info":
            self.ok({"application": "2.5.2", "deviceKey": "must-not-be-exposed"})
        elif path == "vm/gpio":
            self.ok({"pwr": self.state["power"], "hdd": False})
        elif path == "stream/mjpeg":
            self.set_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.set_header("Cache-Control", "no-store")
            try:
                while not self.state["end_video"]:
                    jpeg = self.state["jpeg"]
                    self.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                               + str(len(jpeg)).encode() + b"\r\n\r\n" + jpeg + b"\r\n")
                    await self.flush()
                    await asyncio.sleep(0.02)
            except (iostream.StreamClosedError, asyncio.CancelledError):
                pass
        else:
            raise web.HTTPError(404)


class FakeInput(websocket.WebSocketHandler):
    def initialize(self, state):
        self.state = state

    def prepare(self):
        if self.get_cookie("nano-kvm-token") != "test-session" or self.state["revoked"]:
            raise web.HTTPError(401)

    def open(self):
        self.state["connections"] += 1
        self.state["backend"] = self
        self.write_message({"type": "keyboard_led", "data": "{}"})

    def on_message(self, message):
        self.state["reports"].append(message)

    def on_close(self):
        self.state["connections"] -= 1

AUTH = {"X-KVMD-User": USER, "X-KVMD-Passwd": PASSWORD}


class BridgeTests(testing.AsyncHTTPTestCase):
    def get_app(self):
        self.clients = []
        self.state = dict(logins=0, power=False, pulses=[], reports=[], connections=0,
                          revoked=False, cookie_auth=True, jpeg=JPEG, end_video=False, paste=[], hdmi=True,
                          screen=[], screen_failure=False, capture_resets=0)
        upstream = web.Application([
            (r'/api/ws', FakeInput, {'state': self.state}),
            (r'/api/(.*)', FakeNano, {'state': self.state}),
        ])
        sock = netutil.bind_sockets(0, '127.0.0.1')[0]
        port = sock.getsockname()[1]
        self.upstream = httpserver.HTTPServer(upstream)
        self.upstream.add_socket(sock)
        self.nano = bridge.NanoKVM(f'http://127.0.0.1:{port}', None)
        return bridge.application(self.nano)

    def tearDown(self):
        for client in self.clients:
            client.close()
        if self.nano.controller:
            self.io_loop.run_sync(self.nano.controller.close)
        for source in list(self.nano.streams):
            source.close()
        self.state['end_video'] = True
        self.upstream.stop()
        self.io_loop.run_sync(self.upstream.close_all_connections)
        self.nano.http.close()
        super().tearDown()

    def result(self, path, **kwargs):
        response = self.fetch(path, headers=AUTH, **kwargs)
        self.assertEqual(response.code, 200, response.body)
        return json.loads(response.body)['result']

    async def wait_for(self, predicate):
        async def poll():
            while not predicate():
                await asyncio.sleep(0.01)
        await asyncio.wait_for(poll(), 2)

    async def connect_input(self, headers=AUTH):
        url = self.get_url('/api/ws').replace('http://', 'ws://')
        client = await websocket.websocket_connect(httpclient.HTTPRequest(url, headers=headers))
        self.clients.append(client)
        events = {}
        while 'streamer_state' not in events:
            message = json.loads(await client.read_message())
            events[message['event_type']] = message['event']
        return client, events

    def test_auth_required_including_video_and_unknown_api(self):
        for path in ('/api/info', '/api/auth/check', '/api/ws', '/streamer/stream', '/streamer/snapshot'):
            self.assertEqual(self.fetch(path).code, 401)
        self.assertEqual(self.fetch('/').code, 200)
        self.assertEqual(self.state['logins'], 0)
        self.assertEqual(self.fetch('/api/no-such-feature', headers=AUTH).code, 501)

    def test_login_cookie_basic_headers_and_logout(self):
        response = self.fetch('/api/auth/login', method='POST', body=urlencode({'user': USER, 'passwd': PASSWORD}))
        self.assertEqual(response.code, 200)
        cookie_header = response.headers['Set-Cookie']
        self.assertIn('Secure', cookie_header)
        self.assertIn('HttpOnly', cookie_header)
        cookie = cookie_header.split(';')[0]
        headers = {'Cookie': cookie}
        self.assertEqual(self.fetch('/api/auth/check', headers=headers).code, 200)
        basic = {'Authorization': 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()}
        self.assertEqual(self.fetch('/api/auth/check', headers=basic).code, 200)
        self.assertEqual(self.fetch('/api/auth/check', headers=AUTH).code, 200)
        self.assertEqual(self.state['logins'], 1)
        self.assertEqual(self.fetch('/api/auth/logout', method='POST', body='', headers=headers).code, 200)
        self.assertEqual(self.fetch('/api/auth/check', headers=headers).code, 401)
        self.assertEqual(self.fetch('/api/auth/login', method='POST', body='[]', headers={'Content-Type': 'application/json'}).code, 400)

    def test_rejected_password_disabled_auth_and_session_revocation(self):
        bad = dict(AUTH, **{'X-KVMD-Passwd': PASSWORD[:-1]})
        self.assertEqual(self.fetch('/api/auth/check', headers=bad).code, 403)
        self.state['cookie_auth'] = False
        self.assertEqual(self.fetch('/api/auth/check', headers=AUTH).code, 502)
        self.state['cookie_auth'] = True
        self.result('/api/auth/check')
        self.state['revoked'] = True
        self.assertEqual(self.fetch('/api/auth/check', headers=AUTH).code, 403)
        self.assertEqual(self.fetch('/streamer/snapshot', headers=AUTH).code, 403)

    def test_cross_origin_cookie_writes_rejected(self):
        headers = dict(AUTH, Origin='https://unrelated.example')
        response = self.fetch('/api/atx/click?button=power', headers=headers, method='POST', body='')
        self.assertEqual(response.code, 403)
        self.assertEqual(self.state['pulses'], [])

    def test_info_state_and_snapshot(self):
        info = self.result('/api/info')
        self.assertNotIn('deviceKey', json.dumps(info))
        self.assertEqual(info['bridge']['upstream_version'], '2.5.2')
        self.assertEqual(list(self.result('/api/info?fields=system')), ['system'])
        self.assertEqual(self.result('/api/atx')['leds'], {'power': False, 'hdd': False})
        self.assertTrue(self.result('/api/hid')['mouse']['absolute'])
        self.assertFalse(self.result('/api/msd')['enabled'])
        self.assertEqual(self.result('/api/streamer')['streamer']['source']['resolution'], {'width': 16, 'height': 12})
        for path in ('/streamer/snapshot', '/streamer?action=snapshot'):
            response = self.fetch(path, headers=AUTH)
            self.assertEqual(response.code, 200)
            self.assertEqual(response.body, JPEG)
        self.assertEqual(self.state['reports'], [])

    def test_capture_settings_translation_and_state(self):
        self.result('/api/streamer/set_params?desired_fps=20&quality=76&resolution=1280x720',
                    method='POST', body='')
        self.assertEqual(self.state['screen'], [
            {'type': 'fps', 'value': 20}, {'type': 'quality', 'value': 80},
            {'type': 'resolution', 'value': 720},
        ])
        state = self.result('/api/streamer')
        self.assertEqual(state['params'], {'desired_fps': 20, 'quality': 80, 'resolution': '1280x720'})
        self.assertTrue(state['features']['quality'])
        self.assertTrue(state['features']['resolution'])
        # Actual JPEG dimensions remain separate from the requested capture mode.
        self.assertEqual(state['streamer']['source']['resolution'], {'width': 16, 'height': 12})
        self.assertEqual(self.state['reports'], [])
        self.assertEqual(self.state['pulses'], [])

    def test_capture_limits(self):
        for request, expected in [('desired_fps=0', 60), ('desired_fps=1', 10),
                                  ('desired_fps=120', 60), ('quality=1', 50), ('quality=100', 100)]:
            self.result('/api/streamer/set_params?' + request, method='POST', body='')
            self.assertEqual(self.state['screen'][-1]['value'], expected)

    def test_invalid_capture_request_has_no_partial_writes(self):
        for query, code in [('quality=80&resolution=123x456', 400),
                            ('desired_fps=20&quality=101', 400), ('desired_fps=-1', 400),
                            ('quality=80&h264_bitrate=1000', 501)]:
            response = self.fetch('/api/streamer/set_params?' + query,
                                  method='POST', body='', headers=AUTH)
            self.assertEqual(response.code, code)
        self.assertEqual(self.state['screen'], [])

    def test_failed_capture_update_does_not_report_success(self):
        self.state['screen_failure'] = True
        response = self.fetch('/api/streamer/set_params?quality=50', method='POST', body='', headers=AUTH)
        self.assertEqual(response.code, 502)
        self.assertEqual(self.result('/api/streamer')['params']['quality'], 80)

    def test_capture_reset_requires_auth_and_only_resets_capture(self):
        self.assertEqual(self.fetch('/api/streamer/reset', method='POST', body='').code, 401)
        self.assertEqual(self.state['capture_resets'], 0)
        self.result('/api/streamer/reset', method='POST', body='')
        self.assertEqual(self.state['capture_resets'], 1)
        self.assertEqual(self.state['pulses'], [])
        self.assertEqual(self.state['reports'], [])

    @testing.gen_test
    async def test_no_hdmi_does_not_block_input_or_power_state(self):
        self.state['hdmi'] = False
        self.state['end_video'] = True
        client, events = await self.connect_input()
        self.assertIsNone(events['streamer_state']['streamer'])
        self.assertTrue(events['atx_state']['enabled'])
        self.assertEqual(self.state['reports'], [])
        client.close()
        await self.wait_for(lambda: self.nano.controller is None)

    @testing.gen_test
    async def test_multipart_stream_and_cleanup(self):
        chunks = []
        def collect(chunk):
            chunks.append(chunk)
            self.state['end_video'] = True
        response = await self.http_client.fetch(httpclient.HTTPRequest(
            self.get_url('/streamer/stream'), headers=AUTH, streaming_callback=collect), raise_error=False)
        self.assertEqual(response.code, 200)
        data = b''.join(chunks)
        self.assertIn(b'Content-Length: ' + str(len(JPEG)).encode(), data)
        self.assertIn(JPEG, data)
        await self.wait_for(lambda: not self.nano.streams)

    def test_power_idempotence_and_explicit_hard_actions(self):
        for action in ('on', 'on', 'off', 'off'):
            self.result('/api/atx/power?action=' + action, method='POST', body='')
        self.result('/api/atx/click?button=reset', method='POST', body='')
        self.result('/api/atx/click?button=power_long', method='POST', body='')
        self.assertEqual(self.state['pulses'], [
            {'type': 'power', 'duration': 800}, {'type': 'power', 'duration': 800},
            {'type': 'reset', 'duration': 800}, {'type': 'power', 'duration': 5000},
        ])
        self.assertEqual(self.fetch('/api/atx/power?action=invalid', method='POST', body='', headers=AUTH).code, 400)

    @testing.gen_test
    async def test_json_input_reports_and_disconnect_cleanup(self):
        client, events = await self.connect_input()
        self.assertIn('loop', events)
        self.assertEqual(events['atx_state']['leds'], {'power': False, 'hdd': False})
        for kind, data in [
            ('key', {'key': 'ControlLeft', 'state': True}),
            ('key', {'key': 'KeyA', 'state': True}),
            ('mouse_move', {'to': {'x': 32767, 'y': -32768}}),
            ('mouse_button', {'button': 'right', 'state': True}),
            ('mouse_wheel', {'delta': {'x': 0, 'y': -3}}),
        ]:
            await client.write_message(json.dumps({'event_type': kind, 'event': data}))
        await self.wait_for(lambda: len(self.state['reports']) == 5)
        self.assertEqual(self.state['reports'][0], bytes([1, 1, 0, 0, 0, 0, 0, 0, 0]))
        self.assertEqual(self.state['reports'][1], bytes([1, 1, 0, 4, 0, 0, 0, 0, 0]))
        self.assertEqual(self.state['reports'][2], bytes([2, 0, 255, 127, 0, 0, 0]))
        self.assertEqual(self.state['reports'][4], bytes([2, 2, 255, 127, 0, 0, 253]))
        client.close()
        await self.wait_for(lambda: self.nano.controller is None and self.state['connections'] == 0)
        self.assertEqual(self.state['reports'][-2:], [bytes([1] + [0] * 8), bytes([2, 0, 255, 127, 0, 0, 0])])

    @testing.gen_test
    async def test_binary_input_finish_and_ping(self):
        client, _ = await self.connect_input()
        for message in (b'\x01\x03KeyA', b'\x03\x80\x00\x7f\xff', b'\x02\x01left', b'\x05\x00\x00\x01'):
            await client.write_message(message, binary=True)
        await self.wait_for(lambda: len(self.state['reports']) == 5)
        self.assertEqual(self.state['reports'][0], bytes([1, 0, 0, 4, 0, 0, 0, 0, 0]))
        self.assertEqual(self.state['reports'][1], bytes([1] + [0] * 8))
        self.assertEqual(self.state['reports'][2], bytes([2, 0, 0, 0, 255, 127, 0]))
        await client.write_message(b'\x00', binary=True)
        self.assertEqual(await client.read_message(), b'\xff')
        await client.write_message('{"event_type":"ping","event":{}}')
        self.assertEqual(json.loads(await client.read_message())['event_type'], 'pong')
        client.close()
        await self.wait_for(lambda: self.nano.controller is None)

    @testing.gen_test
    async def test_idle_and_invalid_input_send_no_hid(self):
        client, _ = await self.connect_input()
        for message in ('[]', '{}', '{"event_type":"key","event":{"key":"KeyA","state":true,"finish":"invalid"}}'):
            await client.write_message(message)
            self.assertEqual(json.loads(await client.read_message())['event_type'], 'error')
        client.close()
        await self.wait_for(lambda: self.nano.controller is None)
        self.assertEqual(self.state['reports'], [])

    def test_http_input_shortcuts_and_paste(self):
        self.result('/api/hid/events/send_shortcut?keys=ControlLeft,AltLeft,Delete', method='POST', body='')
        self.result('/api/hid/events/send_mouse_move?to_x=0&to_y=0', method='POST', body='')
        self.result('/api/hid/print?keymap=en-us', method='POST', body='hello')
        self.io_loop.run_sync(lambda: self.wait_for(lambda: len(self.state['reports']) >= 7))
        self.assertEqual(self.state['reports'][2], bytes([1, 5, 0, 76, 0, 0, 0, 0, 0]))
        self.assertEqual(self.state['reports'][5], bytes([1] + [0] * 8))
        self.assertEqual(self.state['reports'][6], bytes([2, 0, 0, 64, 0, 64, 0]))
        self.assertEqual(self.state['paste'], [{'content': 'hello', 'langue': 'en'}])

    @testing.gen_test
    async def test_second_websocket_and_backend_failure(self):
        first, _ = await self.connect_input()
        url = self.get_url('/api/ws').replace('http://', 'ws://')
        second = await websocket.websocket_connect(httpclient.HTTPRequest(url, headers=AUTH))
        self.assertIsNone(await second.read_message())
        self.assertEqual(second.close_code, 1013)
        second.close()
        self.state['backend'].close()
        self.assertIsNone(await first.read_message())
        await self.wait_for(lambda: self.nano.controller is None)

    @testing.gen_test
    async def test_live_authorization_revocation_releases_keys(self):
        client, _ = await self.connect_input()
        await client.write_message(b'\x01\x01KeyA', binary=True)
        await self.wait_for(lambda: len(self.state['reports']) == 1)
        self.state['revoked'] = True
        await self.nano.controller.tick()
        await self.wait_for(lambda: self.nano.controller is None and self.state['connections'] == 0)
        self.assertEqual(self.state['reports'][-1], bytes([1] + [0] * 8))
        self.assertIsNone(await client.read_message())


class InputUnitTests(unittest.TestCase):
    def test_local_capture_settings_and_h264_bitrate(self):
        # NanoKVM stores H.264 bitrate in the same file as JPEG quality.
        nano = object.__new__(bridge.NanoKVM)
        nano.screen = {'desired_fps': 30, 'quality': 80, 'resolution': ''}
        with tempfile.TemporaryDirectory() as directory:
            for name, value in [('fps', '60'), ('qlty', '5000'), ('res', '0')]:
                (Path(directory) / name).write_text(value)
            nano.load_screen(directory)
            self.assertEqual(nano.screen, {'desired_fps': 60, 'quality': 80, 'resolution': ''})
            (Path(directory) / 'qlty').write_text('50')
            (Path(directory) / 'res').write_text('720')
            nano.load_screen(directory)
            self.assertEqual(nano.screen['quality'], 50)
            self.assertEqual(nano.screen['resolution'], '1280x720')

    def test_boundary_and_invalid_binary_input(self):
        for value in (b'', b'\x03\x00', b'\x01\x80\x00\x01', b'\x05\x00\x00'):
            with self.assertRaises(ValueError):
                bridge.binary_event(value)
        state = bridge.InputState()
        for letter in 'ABCDEF':
            state.translate('key_down', {'code': 'Key' + letter})
        with self.assertRaises(ValueError):
            state.translate('key_down', {'code': 'KeyG'})
        with self.assertRaises(ValueError):
            bridge.input_reports(state, 'mouse_move', {'to': {'x': 32768, 'y': 0}}, (16, 12))
        self.assertEqual(state.release(), [bytes([1] + [0] * 8)])

    def test_jpeg_header_without_decoding(self):
        self.assertEqual(bridge.jpeg_size(JPEG), (16, 12))
        with self.assertRaises(ValueError):
            bridge.jpeg_size(JPEG[:-2])


if __name__ == '__main__':
    unittest.main()
