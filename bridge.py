#!/usr/bin/env python3
"""Single-file PiKVM API and encrypted VNC adapter for original NanoKVM."""

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import logging
import os
import signal
import socket
import ssl
import struct
import secrets
import time
import tempfile
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import quote, urlsplit

from tornado import httpclient, httpserver, ioloop, iostream, tcpserver, web, websocket

VERSION = "0.5.0"
MAX_JPEG = 4 * 1024 * 1024 - 1  # Tight compact-length limit
PIXEL_FORMAT = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
RESOLUTIONS = {'640x480': 480, '800x600': 600, '1280x720': 720, '1920x1080': 1080}
QUALITIES = (50, 60, 80, 100)
LOG = logging.getLogger("nanokvm-touch")


async def encode_password(password):
    """Produce NanoKVM's CryptoJS/OpenSSL-compatible password envelope.

    The public passphrase is a wire-format convention, not transport security.
    Derive the IV here so OpenSSL's version-dependent salt length is irrelevant.
    Password bytes go to stdin, never a command-line argument or a file.
    """
    salt = os.urandom(8)
    material = previous = b""
    while len(material) < 48:
        previous = hashlib.md5(previous + b"nanokvm-sipeed-2024" + salt).digest()
        material += previous
    process = await asyncio.create_subprocess_exec(
        "openssl", "enc", "-aes-256-cbc", "-nosalt",
        "-K", material[:32].hex(), "-iv", material[32:48].hex(),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    ciphertext, _ = await process.communicate(password.encode())
    if process.returncode:
        raise web.HTTPError(502, reason="Password encoding failed")
    return quote(base64.b64encode(b"Salted__" + salt + ciphertext).decode(), safe="")


@dataclass
class Session:
    cookie: str
    expires: float


class NanoKVM:
    def __init__(self, upstream, tls):
        self.upstream = upstream.rstrip("/")
        self.tls = tls
        self.http = httpclient.AsyncHTTPClient(force_instance=True, max_clients=8)
        self.sessions = {}
        self.cache_key = os.urandom(32)
        self.login_lock = asyncio.Lock()
        self.controller = None
        self.vnc_client = None
        self.control_lock = asyncio.Lock()
        self.power_lock = asyncio.Lock()
        self.tokens = {}
        self.streams = set()
        self.size = (0, 0)
        self.screen_lock = asyncio.Lock()
        self.screen = {'desired_fps': 30, 'quality': 80, 'resolution': ''}

    def load_screen(self, directory):
        """Read local startup settings; NanoKVM has no screen-settings GET API."""
        for name, filename in (('desired_fps', 'fps'), ('quality', 'qlty'), ('resolution', 'res')):
            try:
                value = int((Path(directory) / filename).read_text().strip())
            except (OSError, ValueError):
                continue
            if name == 'desired_fps':
                self.screen[name] = max(10, min(60, value))
            elif name == 'quality' and value in QUALITIES:
                self.screen[name] = value
            elif name == 'resolution':
                self.screen[name] = next((r for r, h in RESOLUTIONS.items() if h == value), '')

    def request(self, path, session=None, method="GET", data=None):
        headers = {"Accept": "application/json"}
        if session:
            headers["Cookie"] = session.cookie
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = json.dumps(data or {})
        return httpclient.HTTPRequest(
            self.upstream + path, method=method, headers=headers, body=body,
            ssl_options=self.tls, connect_timeout=5, request_timeout=15,
            follow_redirects=False,
        )

    async def fetch(self, request):
        try:
            response = await self.http.fetch(request, raise_error=False)
        except (httpclient.HTTPClientError, OSError):
            raise web.HTTPError(502, reason="NanoKVM is unreachable") from None
        if response.code in (401, 403):
            raise web.HTTPError(403, reason="NanoKVM rejected this session or operation")
        if response.code != 200:
            raise web.HTTPError(502, reason="Unexpected NanoKVM HTTP response")
        try:
            result = json.loads(response.body)
            if not isinstance(result, dict):
                raise ValueError
        except (ValueError, TypeError):
            raise web.HTTPError(502, reason="Invalid NanoKVM response") from None
        return response, result

    async def login(self, username, password):
        digest = hmac.digest(
            self.cache_key, json.dumps([username, password]).encode(), "sha256"
        )
        async with self.login_lock:
            now = time.monotonic()
            self.sessions = {k: s for k, s in self.sessions.items() if s.expires > now}
            if digest in self.sessions:
                return self.sessions[digest]
            response, result = await self.fetch(self.request(
                "/api/auth/login", method="POST",
                data={"username": username, "password": await encode_password(password)},
            ))
            if result.get("code") != 0:
                raise web.HTTPError(403, reason="NanoKVM login failed")
            cookies = SimpleCookie()
            for header in response.headers.get_list("Set-Cookie"):
                cookies.load(header)
            # No cookie means authentication is disabled or this firmware is unsupported.
            if not cookies:
                raise web.HTTPError(502, reason="NanoKVM must have cookie authentication enabled")
            cookie = "; ".join(f"{k}={v.value}" for k, v in cookies.items())
            session = Session(cookie, now + 300)
            if len(self.sessions) >= 32:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[digest] = session
            return session

    async def api(self, path, session, method="GET", data=None):
        _, result = await self.fetch(self.request(path, session, method, data))
        if result.get("code") != 0:
            raise web.HTTPError(502, reason="NanoKVM could not perform this operation")
        return result.get("data") or {}


# USB HID keyboard usage IDs (USB HID Usage Tables, Keyboard/Keypad page).
# These are protocol constants; no upstream application's code is vendored.
KEYS = {f"Key{chr(65 + n)}": 4 + n for n in range(26)}
KEYS.update({f"Digit{n}": 29 + n for n in range(1, 10)})
KEYS["Digit0"] = 39
KEYS.update({f"F{n}": 57 + n for n in range(1, 13)})
KEYS.update({f"F{n}": 91 + n for n in range(13, 25)})
KEYS.update({
    "Enter": 40, "Escape": 41, "Backspace": 42, "Tab": 43, "Space": 44,
    "Minus": 45, "Equal": 46, "BracketLeft": 47, "BracketRight": 48,
    "Backslash": 49, "Semicolon": 51, "Quote": 52, "Backquote": 53,
    "Comma": 54, "Period": 55, "Slash": 56, "CapsLock": 57,
    "PrintScreen": 70, "ScrollLock": 71, "Pause": 72, "Insert": 73,
    "Home": 74, "PageUp": 75, "Delete": 76, "End": 77, "PageDown": 78,
    "ArrowRight": 79, "ArrowLeft": 80, "ArrowDown": 81, "ArrowUp": 82,
    "NumLock": 83, "NumpadDivide": 84, "NumpadMultiply": 85,
    "NumpadSubtract": 86, "NumpadAdd": 87, "NumpadEnter": 88,
    "Numpad0": 98, "NumpadDecimal": 99, "IntlBackslash": 100,
    "ContextMenu": 101, "NumpadEqual": 103,
})
KEYS.update({f"Numpad{n}": 88 + n for n in range(1, 10)})
MODIFIERS = {name: 1 << n for n, name in enumerate((
    "ControlLeft", "ShiftLeft", "AltLeft", "MetaLeft",
    "ControlRight", "ShiftRight", "AltRight", "MetaRight",
))}


class InputState:
    def __init__(self):
        self.keys = set()
        self.modifiers = self.buttons = self.x = self.y = 0
        self.keyboard_used = self.mouse_used = False

    def keyboard(self):
        return bytes([1, self.modifiers, 0] + sorted(self.keys) + [0] * (6 - len(self.keys)))

    def mouse(self, wheel=0):
        return struct.pack("<BBHHb", 2, self.buttons, self.x, self.y, wheel)

    def translate(self, event, data):
        if event in ("key_down", "key_up"):
            key = data["code"]
            down = event == "key_down"
            if key in MODIFIERS:
                bit = MODIFIERS[key]
                self.modifiers = (self.modifiers | bit) if down else (self.modifiers & ~bit)
            else:
                code = KEYS[key]
                if down:
                    if code not in self.keys and len(self.keys) == 6:
                        raise ValueError("Six non-modifier keys are already held")
                    self.keys.add(code)
                else:
                    self.keys.discard(code)
            self.keyboard_used = True
            return self.keyboard()
        if event == "mouse_move":
            x, y = data["x"], data["y"]
            if type(x) is not int or type(y) is not int or not (0 <= x <= 32767 and 0 <= y <= 32767):
                raise ValueError("Coordinates must be integers from 0 to 32767")
            self.x, self.y = x, y
        elif event == "mouse_button":
            bit = {"left": 1, "right": 2, "middle": 4}[data["button"]]
            if type(data["pressed"]) is not bool:
                raise ValueError("pressed must be a boolean")
            self.buttons = (self.buttons | bit) if data["pressed"] else (self.buttons & ~bit)
        elif event == "mouse_wheel":
            delta = data["delta"]
            if type(delta) is not int or not -127 <= delta <= 127:
                raise ValueError("Wheel delta must be an integer from -127 to 127")
            self.mouse_used = True
            return self.mouse(delta)
        else:
            raise ValueError("Unsupported input event")
        self.mouse_used = True
        return self.mouse()

    def release(self):
        self.keys.clear()
        self.modifiers = self.buttons = 0
        return ([self.keyboard()] if self.keyboard_used else []) + ([self.mouse()] if self.mouse_used else [])


# X11 keysyms used by RFB, mapped independently to USB usages (US layout).
SYMBOLS = {ord(c): (4 + n, False) for n, c in enumerate('abcdefghijklmnopqrstuvwxyz')}
SYMBOLS.update({ord(c): (4 + n, True) for n, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')})
for plain, shifted, name in zip('1234567890-=[]\\;\'`,./', '!@#$%^&*()_+{}|:"~<>?',
                                ['Digit' + c for c in '1234567890'] + [
                                    'Minus', 'Equal', 'BracketLeft', 'BracketRight',
                                    'Backslash', 'Semicolon', 'Quote', 'Backquote',
                                    'Comma', 'Period', 'Slash']):
    SYMBOLS[ord(plain)] = (KEYS[name], False)
    SYMBOLS[ord(shifted)] = (KEYS[name], True)
SYMBOLS[32] = (44, False)
for sym, name in {
    0xff08: 'Backspace', 0xff09: 'Tab', 0xff0d: 'Enter', 0xff1b: 'Escape',
    0xffff: 'Delete', 0xff50: 'Home', 0xff51: 'ArrowLeft', 0xff52: 'ArrowUp',
    0xff53: 'ArrowRight', 0xff54: 'ArrowDown', 0xff55: 'PageUp', 0xff56: 'PageDown',
    0xff57: 'End', 0xff63: 'Insert', 0xffe5: 'CapsLock', 0xff7f: 'NumLock',
    0xff14: 'ScrollLock', 0xff13: 'Pause', 0xff61: 'PrintScreen', 0xff67: 'ContextMenu',
    0xff8d: 'NumpadEnter', 0xffaa: 'NumpadMultiply', 0xffab: 'NumpadAdd',
    0xffad: 'NumpadSubtract', 0xffae: 'NumpadDecimal', 0xffaf: 'NumpadDivide',
    0xffbd: 'NumpadEqual',
    **{0xffbe + n: f'F{n + 1}' for n in range(24)},
    **{0xffb0 + n: f'Numpad{n}' for n in range(10)},
}.items():
    SYMBOLS[sym] = (KEYS[name], False)
KEYSYM_MODIFIERS = {
    0xffe1: 2, 0xffe2: 32, 0xffe3: 1, 0xffe4: 16,
    0xffe9: 4, 0xffea: 64, 0xffeb: 8, 0xffec: 128,
    0xffe7: 8, 0xffe8: 128, 0xfe03: 64,
}


class VNCInputState(InputState):
    def __init__(self):
        super().__init__()
        self.held = {}
        self.wheel_mask = 0

    def keyboard(self):
        modifiers = 0
        usages = set()
        for sym, (usage, shift) in self.held.items():
            if sym in KEYSYM_MODIFIERS:
                modifiers |= KEYSYM_MODIFIERS[sym]
            else:
                usages.add(usage)
                if shift:
                    modifiers |= 2
        return bytes([1, modifiers, 0] + sorted(usages) + [0] * (6 - len(usages)))

    def key(self, sym, down):
        if sym & 0xff000000 == 0x01000000:
            sym &= 0xffffff  # Unicode keysyms for supported ASCII characters
        if not down:
            if sym not in self.held:
                return None
            del self.held[sym]
        elif sym in KEYSYM_MODIFIERS:
            self.held[sym] = (0, False)
        elif sym in SYMBOLS:
            usages = {value[0] for key, value in self.held.items() if key not in KEYSYM_MODIFIERS}
            if SYMBOLS[sym][0] not in usages and len(usages) >= 6:
                return None
            self.held[sym] = SYMBOLS[sym]
        else:
            return None
        self.keyboard_used = True
        return self.keyboard()

    def pointer(self, mask, x, y, width, height):
        self.x = min(x, width - 1) * 32767 // max(1, width - 1)
        self.y = min(y, height - 1) * 32767 // max(1, height - 1)
        self.buttons = (mask & 1) | ((mask & 2) << 1) | ((mask & 4) >> 1)
        rising = mask & ~self.wheel_mask
        wheel = int(bool(rising & 8)) - int(bool(rising & 16))
        self.wheel_mask = mask
        self.mouse_used = True
        return self.mouse(wheel)

    def release(self):
        self.held.clear()
        return super().release()


def jpeg_size(data):
    """Read JPEG frame dimensions without decoding pixels."""
    if not data.startswith(b'\xff\xd8') or not data.endswith(b'\xff\xd9'):
        raise ValueError('Incomplete JPEG')
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 255:
            break
        while pos < len(data) and data[pos] == 255:
            pos += 1
        marker = data[pos]
        pos += 1
        if marker in (0xd9, 0xda):
            break
        length = int.from_bytes(data[pos:pos + 2], 'big')
        if length < 2 or pos + length > len(data):
            break
        if marker in (0xc0, 0xc1, 0xc2):
            if length < 8:
                break
            height, width = struct.unpack('>HH', data[pos + 3:pos + 7])
            if not (1 <= width <= 2048 and 1 <= height <= 2160):
                raise ValueError('Unsupported dimensions (maximum 2048x2160)')
            return width, height
        pos += length
    raise ValueError('JPEG dimensions missing')



def compact_length(length):
    if not 0 <= length <= MAX_JPEG:
        raise ValueError('JPEG exceeds Tight length limit')
    if length < 128:
        return bytes([length])
    if length < 16384:
        return bytes([(length & 127) | 128, length >> 7])
    return bytes([(length & 127) | 128, ((length >> 7) & 127) | 128, length >> 14])


class MJPEG:
    """Bounded, sequential reads in a worker thread; no pixel decoder needed."""
    def __init__(self, nano, session):
        target = urlsplit(nano.upstream)
        args = dict(host=target.hostname, port=target.port, timeout=20)
        if target.scheme == 'https':
            self.connection = http.client.HTTPSConnection(**args, context=nano.tls)
        else:
            self.connection = http.client.HTTPConnection(**args)
        self.cookie = session.cookie
        self.response = None
        self.closed = False

    def read(self):
        if self.closed:
            raise EOFError('Video closed')
        if self.response is None:
            self.connection.request('GET', '/api/stream/mjpeg', headers={'Cookie': self.cookie})
            self.response = self.connection.getresponse()
            if self.closed:
                self.connection.close()
                raise EOFError('Video closed')
            if self.response.status != 200 or not self.response.getheader('Content-Type', '').startswith('multipart/x-mixed-replace'):
                raise ValueError('NanoKVM did not return MJPEG')
        # NanoKVM sends Content-Length for every frame; cap headers and payload.
        length = None
        total = 0
        while total < 8192:
            line = self.response.readline(1024)
            total += len(line)
            if not line:
                raise EOFError('NanoKVM ended video')
            if line in (b'\r\n', b'\n') and length is not None:
                break
            if line.lower().startswith(b'content-length:'):
                length = int(line.split(b':', 1)[1])
                if not 1 <= length <= MAX_JPEG:
                    raise ValueError('Invalid JPEG length')
        else:
            raise ValueError('MJPEG header too large')
        data = self.response.read(length)
        if len(data) != length:
            raise EOFError('Incomplete video frame')
        return data, jpeg_size(data)

    def close(self):
        self.closed = True
        # Interrupt a worker blocked in read before closing its buffered reader.
        sock = self.connection.sock
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        self.connection.close()



def boolean(value):
    if value in (True, 'true', '1', 1):
        return True
    if value in (False, 'false', '0', 0):
        return False
    raise ValueError('Expected boolean')


def number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('Expected integer')
    value = int(value)
    if not low <= value <= high:
        raise ValueError('Out of range')
    return value


def input_reports(state, kind, data, size):
    if kind == 'key':
        key, down = data['key'], boolean(data['state'])
        finish = boolean(data.get('finish', False))
        reports = [state.translate('key_down' if down else 'key_up', {'code': key})]
        if down and finish and key not in MODIFIERS and key != 'PrintScreen':
            reports.append(state.translate('key_up', {'code': key}))
        return reports
    if kind == 'mouse_button':
        return [state.translate(kind, {'button': data['button'], 'pressed': boolean(data['state'])})]
    if kind == 'mouse_move':
        to = {axis: (number(data['to'][axis], -32768, 32767) + 32768) // 2 for axis in ('x', 'y')}
        return [state.translate(kind, to)]
    if kind in ('mouse_relative', 'mouse_wheel'):
        deltas = data['delta'] if isinstance(data['delta'], list) else [data['delta']]
        if len(deltas) > 128:
            raise ValueError('Too many deltas')
        deltas = [(number(d['x'], -127, 127), number(d['y'], -127, 127)) for d in deltas]
        if kind == 'mouse_wheel' and any(x for x, _ in deltas):
            raise ValueError('Horizontal wheel unsupported')
        reports = []
        for x, y in deltas:
            if kind == 'mouse_wheel':
                reports.append(state.translate(kind, {'delta': y}))
            else:
                width, height = size
                to = {'x': max(0, min(32767, state.x + x * 32767 // max(1, width - 1))),
                      'y': max(0, min(32767, state.y + y * 32767 // max(1, height - 1)))}
                reports.append(state.translate('mouse_move', to))
        return reports
    raise ValueError('Unsupported input')


def binary_event(raw):
    if not raw:
        raise ValueError('Empty input')
    kind = raw[0]
    if kind == 0 and len(raw) == 1:
        return 'ping', {}
    if kind in (1, 2) and 3 <= len(raw) <= 34 and raw[1] < 4:
        name = raw[2:].decode('ascii')
        return ('key' if kind == 1 else 'mouse_button', {
            'key' if kind == 1 else 'button': name,
            'state': bool(raw[1] & 1), 'finish': bool(raw[1] & 2),
        })
    if kind == 3 and len(raw) == 5:
        x, y = struct.unpack('>hh', raw[1:])
        return 'mouse_move', {'to': {'x': x, 'y': y}}
    if kind in (4, 5) and 4 <= len(raw) <= 258 and len(raw) % 2 == 0:
        values = struct.iter_unpack('>bb', raw[2:])
        return ('mouse_relative' if kind == 4 else 'mouse_wheel',
                {'delta': [{'x': x, 'y': y} for x, y in values]})
    raise ValueError('Unsupported binary event')


class Controller:
    """One NanoKVM input socket, shared by this session's HTTP and WS calls."""
    def __init__(self, nano, session, backend):
        self.nano, self.session, self.backend = nano, session, backend
        self.state = InputState()
        self.lock = asyncio.Lock()
        self.client = None
        self.closed = False
        self.last_used = time.monotonic()
        self.timer = ioloop.PeriodicCallback(self.tick, 10000)
        self.timer.start()
        self.reader = asyncio.create_task(self.read_backend())

    async def read_backend(self):
        try:
            while await self.backend.read_message() is not None:
                pass
        finally:
            await self.close()

    async def tick(self):
        try:
            if self.client is None and time.monotonic() - self.last_used > 15:
                await self.close()
                return
            await self.nano.api('/api/auth/account', self.session)
            await self.backend.write_message(b'\x00', binary=True)
            if self.client:
                await self.client.event('atx_state', await atx_state(self.nano, self.session))
                await self.client.event('streamer_state', await streamer_state(self.nano, self.session))
        except (web.HTTPError, websocket.WebSocketClosedError):
            await self.close()

    async def send(self, kind, data):
        async with self.lock:
            if self.closed:
                raise web.HTTPError(503, reason='Input connection closed; reconnect')
            self.last_used = time.monotonic()
            for report in input_reports(self.state, kind, data, self.nano.size):
                await self.backend.write_message(report, binary=True)

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.timer.stop()
        async with self.lock:
            try:
                for report in self.state.release():
                    await asyncio.wait_for(self.backend.write_message(report, binary=True), 2)
            except (websocket.WebSocketClosedError, asyncio.TimeoutError):
                pass
            self.backend.close()
        if self.client:
            self.client.close(1001, 'Input session ended')
        if self.nano.controller is self:
            self.nano.controller = None


async def controller(nano, session):
    async with nano.control_lock:
        if nano.vnc_client is not None:
            raise web.HTTPError(409, reason="A VNC input session is active")
        if nano.controller:
            if nano.controller.session.cookie != session.cookie:
                raise web.HTTPError(409, reason='Another input session is active')
            return nano.controller
        request = nano.request('/api/ws', session)
        request.url = request.url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
        try:
            backend = await websocket.websocket_connect(request, max_message_size=65536)
        except (OSError, httpclient.HTTPClientError):
            raise web.HTTPError(502, reason='NanoKVM input unavailable') from None
        nano.controller = Controller(nano, session, backend)
        return nano.controller


async def atx_state(nano, session):
    gpio = await nano.api('/api/vm/gpio', session)
    return {'enabled': True, 'busy': nano.power_lock.locked(),
            'leds': {'power': bool(gpio['pwr']), 'hdd': bool(gpio['hdd'])}}


def hid_state():
    return {'enabled': True, 'online': True, 'busy': False, 'connected': True,
            'keyboard': {'online': True, 'leds': {'caps': False, 'num': False, 'scroll': False},
                         'outputs': {'available': ['usb'], 'active': 'usb'}},
            'mouse': {'online': True, 'absolute': True,
                      'outputs': {'available': ['usb'], 'active': 'usb'}},
            'jiggler': {'enabled': False, 'active': False}}


async def streamer_state(nano, session):
    hdmi = await nano.api('/api/vm/hdmi', session)
    online = bool(hdmi.get('signal', False))
    if online and nano.size == (0, 0):
        source = MJPEG(nano, session)
        try:
            _, nano.size = await asyncio.to_thread(source.read)
        except (OSError, EOFError, ValueError, http.client.HTTPException):
            raise web.HTTPError(502, reason='NanoKVM capture unavailable') from None
        finally:
            source.close()
    width, height = nano.size
    return {'features': {'quality': True, 'resolution': True, 'h264': False},
            'limits': {'max_fps': 60, 'available_resolutions': list(RESOLUTIONS)},
            'params': dict(nano.screen, resolution=nano.screen['resolution'] or f'{width}x{height}'),
            'snapshot': {'saved': None},
            'streamer': None if not online else {'encoder': {'quality': nano.screen['quality']},
                         'source': {'online': True, 'resolution': {'width': width, 'height': height}},
                         'stream': {'clients': len(nano.streams)}}}


class Authenticated:
    async def prepare(self):
        self.nano = self.settings['nano']
        self.set_header('Cache-Control', 'no-store')
        # No cross-origin browser writes with ambient cookies.
        origin = self.request.headers.get('Origin')
        if origin and origin != f'{self.request.protocol}://{self.request.host}':
            raise web.HTTPError(403, reason='Cross-origin requests are not allowed')
        if self.request.path == '/api/auth/login':
            return
        token = self.get_cookie('auth_token', '')
        now = time.monotonic()
        self.nano.tokens = {k: v for k, v in self.nano.tokens.items() if v[1] > now}
        self.session = self.nano.tokens.get(token, (None, 0))[0]
        user = self.request.headers.get('X-KVMD-User', '')
        password = self.request.headers.get('X-KVMD-Passwd', '')
        basic = self.request.headers.get('Authorization', '')
        if not user and basic.lower().startswith('basic '):
            try:
                user, password = base64.b64decode(basic[6:], validate=True).decode().split(':', 1)
            except (ValueError, UnicodeError):
                raise web.HTTPError(401, reason='Invalid credentials') from None
        if user and password:
            self.session = await self.nano.login(user, password)
        if not self.session:
            raise web.HTTPError(401, reason='NanoKVM web login is required')
        await self.nano.api('/api/auth/account', self.session)

    def write_error(self, status_code, **kwargs):
        self.set_header('Content-Type', 'application/json')
        self.finish({'ok': False, 'result': {'error': self._reason}})


class API(Authenticated, web.RequestHandler):
    def ok(self, result=None):
        self.finish({'ok': True, 'result': result or {}})

    async def get(self, path):
        if path == 'auth/check':
            result = {}
        elif path == 'info':
            info = await self.nano.api('/api/vm/info', self.session)
            result = {
                'system': {'kvmd': {'version': VERSION},
                           'streamer': {'app': 'ustreamer', 'version': 'bridge', 'features': {}},
                           'kernel': {'system': 'Linux', 'release': '', 'version': '', 'machine': 'riscv64'}},
                'meta': {'server': {'host': 'NanoKVM'}, 'kvm': {'name': 'NanoKVM TouchKVM bridge'}},
                'hw': {'platform': {'type': 'nanokvm', 'base': 'NanoKVM'}, 'health': {}},
                'extras': {}, 'auth': {'enabled': True},
                'bridge': {'version': VERSION, 'upstream_version': info.get('application')},
            }
            fields = self.get_query_argument('fields', '')
            if fields:
                result = {key: value for key, value in result.items() if key in fields.split(',')}
        elif path == 'atx':
            result = await atx_state(self.nano, self.session)
        elif path == 'hid':
            result = hid_state()
        elif path == 'hid/keymaps':
            result = {'keymaps': {'default': 'en-us', 'available': ['en-us']}}
        elif path == 'streamer':
            result = await streamer_state(self.nano, self.session)
        elif path == 'msd':
            result = {'enabled': False, 'online': False, 'busy': False}
        elif path == 'gpio':
            result = {'model': {'scheme': {'inputs': {}, 'outputs': {}}, 'view': {'header': {}, 'table': []}},
                      'state': {'inputs': {}, 'outputs': {}}}
        else:
            raise web.HTTPError(501, reason='This PiKVM feature is not implemented')
        self.ok(result)

    async def post(self, path):
        try:
            await self.post_impl(path)
        except (ValueError, KeyError, TypeError, UnicodeError, struct.error):
            raise web.HTTPError(400, reason='Invalid or unsupported input') from None

    async def post_impl(self, path):
        if path == 'auth/login':
            if self.request.headers.get('Content-Type', '').startswith('application/json'):
                data = json.loads(self.request.body)
                if not isinstance(data, dict):
                    raise ValueError()
                user, password = data.get('user', ''), data.get('passwd', '')
            else:
                user, password = self.get_body_argument('user', ''), self.get_body_argument('passwd', '')
            if not isinstance(user, str) or not isinstance(password, str) or not user or not password:
                raise web.HTTPError(400, reason='user and passwd are required')
            session = await self.nano.login(user, password)
            await self.nano.api('/api/auth/account', session)
            now = time.monotonic()
            self.nano.tokens = {k: v for k, v in self.nano.tokens.items() if v[1] > now}
            if len(self.nano.tokens) >= 32:
                self.nano.tokens.pop(next(iter(self.nano.tokens)))
            token = secrets.token_hex(32)
            self.nano.tokens[token] = (session, now + 43200)
            self.set_cookie('auth_token', token, secure=True, httponly=True, samesite='Strict', path='/')
        elif path == 'auth/logout':
            self.nano.tokens.pop(self.get_cookie('auth_token', ''), None)
            self.clear_cookie('auth_token', path='/')
            if self.nano.controller and self.nano.controller.session.cookie == self.session.cookie:
                await self.nano.controller.close()
        elif path == 'streamer/set_params':
            # Validate the entire request before changing any shared capture setting.
            changes = []
            for name in self.request.arguments:
                value = self.get_query_argument(name)
                if name == 'desired_fps':
                    value = int(value)
                    if not 0 <= value <= 120:
                        raise ValueError()
                    value = 60 if value == 0 else max(10, min(60, value))
                    kind, native = 'fps', value
                elif name == 'quality':
                    value = int(value)
                    if not 1 <= value <= 100:
                        raise ValueError()
                    value = min(QUALITIES, key=lambda q: abs(q - value))
                    kind, native = 'quality', value
                elif name == 'resolution':
                    kind, native = 'resolution', RESOLUTIONS[value]
                else:
                    raise web.HTTPError(501, reason='Unsupported stream setting')
                changes.append((name, value, kind, native))
            async with self.nano.screen_lock:
                for name, value, kind, native in changes:
                    await self.nano.api('/api/vm/screen', self.session, 'POST', {'type': kind, 'value': native})
                    self.nano.screen[name] = value
                    if name == 'resolution':
                        self.nano.size = (0, 0)
        elif path == 'streamer/reset':
            async with self.nano.screen_lock:
                await self.nano.api('/api/vm/hdmi/reset', self.session, 'POST')
                self.nano.size = (0, 0)
        elif path in ('atx/power', 'atx/click'):
            async with self.nano.power_lock:
                value = self.get_query_argument('action' if path.endswith('power') else 'button')
                duration = 800
                kind = 'power'
                if path == 'atx/power':
                    if value not in ('on', 'off', 'off_hard', 'reset_hard'):
                        raise ValueError()
                    power = (await atx_state(self.nano, self.session))['leds']['power']
                    if (value == 'on' and power) or (value != 'on' and not power):
                        self.ok()
                        return
                    kind = 'reset' if value == 'reset_hard' else 'power'
                    duration = 5000 if value == 'off_hard' else 800
                else:
                    if value not in ('power', 'power_long', 'reset'):
                        raise ValueError()
                    kind = 'reset' if value == 'reset' else 'power'
                    duration = 5000 if value == 'power_long' else 800
                await self.nano.api('/api/vm/gpio', self.session, 'POST', {'type': kind, 'duration': duration})
        elif path.startswith('hid/events/send_'):
            channel = await controller(self.nano, self.session)
            kind = path.removeprefix('hid/events/send_')
            get = self.get_query_argument
            if kind == 'shortcut':
                keys = get('keys').split(',')
                if not 1 <= len(keys) <= 6 or any(k not in KEYS and k not in MODIFIERS for k in keys):
                    raise ValueError()
                for down, sequence in ((True, keys), (False, list(reversed(keys)))):
                    for key in sequence:
                        await channel.send('key', {'key': key, 'state': down})
            elif kind in ('key', 'mouse_button'):
                name = 'key' if kind == 'key' else 'button'
                for down in ([boolean(get('state'))] if 'state' in self.request.arguments else [True, False]):
                    await channel.send(kind, {name: get(name), 'state': down, 'finish': boolean(get('finish', 'false'))})
            elif kind == 'mouse_move':
                await channel.send(kind, {'to': {'x': get('to_x'), 'y': get('to_y')}})
            elif kind in ('mouse_wheel', 'mouse_relative'):
                await channel.send(kind, {'delta': {'x': get('delta_x', '0'), 'y': get('delta_y', '0')}})
            else:
                raise ValueError()
        elif path == 'hid/reset':
            if self.nano.controller and self.nano.controller.session.cookie == self.session.cookie:
                await self.nano.controller.close()
        elif path == 'hid/print':
            text = self.request.body.decode('utf-8')
            if len(text) > 400 or self.get_query_argument('keymap', 'en-us') != 'en-us':
                raise ValueError()
            if text:
                await self.nano.api('/api/hid/paste', self.session, 'POST', {'content': text, 'langue': 'en'})
        elif path == 'hid/set_params':
            # Accept the only advertised output; reject features we cannot set.
            if any(key not in ('keyboard_output', 'mouse_output') or self.get_query_argument(key) != 'usb'
                   for key in self.request.arguments):
                raise web.HTTPError(501, reason='Only USB absolute input is supported')
        else:
            raise web.HTTPError(501, reason='This PiKVM feature is not implemented')
        self.ok()


class Video(Authenticated, web.RequestHandler):
    async def get(self, mode='stream'):
        if len(self.nano.streams) >= 2:
            raise web.HTTPError(503, reason='Two video viewers are already connected')
        source = MJPEG(self.nano, self.session)
        self.nano.streams.add(source)
        checked = time.monotonic()
        try:
            snapshot = mode == 'snapshot' or self.get_query_argument('action', '') == 'snapshot'
            self.set_header('Content-Type', 'image/jpeg' if snapshot else 'multipart/x-mixed-replace; boundary=frame')
            while not self.request.connection.stream.closed():
                jpeg, self.nano.size = await asyncio.to_thread(source.read)
                if time.monotonic() - checked > 10:
                    await self.nano.api('/api/auth/account', self.session)
                    checked = time.monotonic()
                if snapshot:
                    self.finish(jpeg)
                    return
                self.write(b'--frame\r\nContent-Type: image/jpeg\r\nContent-Length: '
                           + str(len(jpeg)).encode() + b'\r\n\r\n' + jpeg + b'\r\n')
                await asyncio.wait_for(self.flush(), 30)
        except EOFError:
            if not self._headers_written:
                raise web.HTTPError(502, reason='NanoKVM video ended before the first frame') from None
            self.finish(b'--frame--\r\n')
        except (OSError, ValueError, http.client.HTTPException, asyncio.TimeoutError,
                iostream.StreamClosedError, web.HTTPError):
            if not self._headers_written:
                raise web.HTTPError(502, reason='NanoKVM video unavailable') from None
            self.request.connection.stream.close()
        finally:
            source.close()
            self.nano.streams.discard(source)


class Input(Authenticated, websocket.WebSocketHandler):
    async def open(self):
        self.channel = None
        try:
            channel = await controller(self.nano, self.session)
            if self.ws_connection is None:
                await channel.close()
                return
            if channel.client is not None:
                self.close(1013, 'Another input socket is connected')
                return
            self.channel = channel
            channel.client = self
            await self.event('loop', {})
            await self.event('hid_state', hid_state())
            await self.event('atx_state', await atx_state(self.nano, self.session))
            await self.event('msd_state', {'enabled': False, 'online': False, 'busy': False})
            await self.event('info_meta_state', {'server': {'host': 'NanoKVM'}, 'kvm': {}})
            await self.event('info_system_state', {'kvmd': {'version': VERSION},
                                                 'streamer': {'app': 'ustreamer', 'version': 'bridge', 'features': {}}})
            await self.event('streamer_state', await streamer_state(self.nano, self.session))
        except (web.HTTPError, OSError, EOFError, ValueError, websocket.WebSocketClosedError):
            self.close(1011, 'NanoKVM connection failed')

    async def event(self, kind, data):
        await self.write_message({'event_type': kind, 'event': data})

    async def on_message(self, raw):
        try:
            if isinstance(raw, bytes):
                kind, data = binary_event(raw)
            else:
                message = json.loads(raw)
                kind, data = message['event_type'], message.get('event', {})
            if kind == 'ping':
                if isinstance(raw, bytes):
                    await self.write_message(b'\xff', binary=True)
                else:
                    await self.event('pong', {})
            else:
                await self.channel.send(kind, data)
        except (ValueError, KeyError, TypeError, UnicodeError, struct.error):
            await self.event('error', {'message': 'Invalid or unsupported input'})
        except (web.HTTPError, websocket.WebSocketClosedError):
            self.close(1011, 'NanoKVM input disconnected')

    def on_close(self):
        channel = getattr(self, 'channel', None)
        if channel and channel.client is self:
            asyncio.create_task(channel.close())


class VNCConnection:
    def __init__(self, server, stream):
        self.server, self.nano, self.stream = server, server.nano, stream
        self.state = VNCInputState()
        self.backend = self.video = None
        self.tasks = []
        self.encodings = set()
        self.frame = None
        self.revision = 0
        self.requested = asyncio.Event()
        self.changed = asyncio.Event()
        self.incremental = False
        self.bounds = (0, 0, 0, 0)
        self.width = self.height = 0
        self.sent_frames = self.sent_bytes = 0

    async def read(self, size):
        return await self.stream.read_bytes(size)

    async def write(self, data):
        await asyncio.wait_for(self.stream.write(data), 30)

    async def handshake(self):
        await self.write(b'RFB 003.008\n')
        if await self.read(12) != b'RFB 003.008\n':
            raise ValueError('RFB 3.8 required')
        await self.write(b'\x01\x13')  # One security type: VeNCrypt (19)
        if await self.read(1) != b'\x13':
            raise ValueError('VeNCrypt required')
        await self.write(b'\x00\x02')
        if await self.read(2) != b'\x00\x02':
            raise ValueError('VeNCrypt 0.2 required')
        await self.write(b'\x00\x01' + struct.pack('>I', 262))  # X509Plain only
        if await self.read(4) != struct.pack('>I', 262):
            raise ValueError('X509Plain required')
        await self.write(b'\x01')
        self.stream = await self.stream.start_tls(True, ssl_options=self.server.tls)
        user_length, pass_length = struct.unpack('>II', await self.read(8))
        if not (1 <= user_length <= 256 and 1 <= pass_length <= 4096):
            raise ValueError('Invalid credential length')
        username = (await self.read(user_length)).decode('utf-8')
        password = (await self.read(pass_length)).decode('utf-8')
        try:
            self.session = await self.nano.login(username, password)
            await self.nano.api('/api/auth/account', self.session)
        except web.HTTPError:
            reason = b'NanoKVM login failed'
            await self.write(struct.pack('>II', 1, len(reason)) + reason)
            raise ValueError('NanoKVM login failed') from None
        finally:
            password = None
        async with self.nano.control_lock:
            if self.nano.controller is not None or self.nano.vnc_client is not None:
                reason = b'Another bridge input client is connected'
                await self.write(struct.pack('>II', 1, len(reason)) + reason)
                raise ValueError('Bridge occupied')
            if len(self.nano.streams) >= 2:
                raise ValueError('Two video viewers are already connected')
            self.nano.vnc_client = self
            self.video = MJPEG(self.nano, self.session)
            self.nano.streams.add(self.video)
        await self.write(b'\x00' * 4)
        await self.read(1)  # ClientInit; this bridge permits one controller.
        self.frame, (self.width, self.height) = await asyncio.to_thread(self.video.read)
        self.nano.size = (self.width, self.height)
        self.revision = 1
        self.frame_size = (self.width, self.height)
        request = self.nano.request('/api/ws', self.session)
        request.url = request.url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
        self.backend = await websocket.websocket_connect(request, max_message_size=65536)
        name = b'NanoKVM bridge'
        await self.write(struct.pack('>HH', self.width, self.height) + PIXEL_FORMAT
                         + struct.pack('>I', len(name)) + name)
        LOG.info('Authenticated VNC session: %dx%d', self.width, self.height)

    async def run(self):
        try:
            # Includes time for bVNC's first-use certificate confirmation dialog.
            await asyncio.wait_for(self.handshake(), 120)
            self.tasks = [asyncio.create_task(fn()) for fn in (
                self.receive, self.capture, self.send_frames, self.keepalive, self.watch_backend)]
            done, _ = await asyncio.wait(self.tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except (OSError, EOFError, ValueError, IndexError, asyncio.TimeoutError,
                iostream.StreamClosedError, websocket.WebSocketClosedError,
                httpclient.HTTPClientError, http.client.HTTPException, web.HTTPError) as exc:
            # Never log request bodies, cookies, input, or exception reprs.
            LOG.info('VNC session closed (%s); sent %d frames, %d JPEG bytes',
                     type(exc).__name__, self.sent_frames, self.sent_bytes)
        finally:
            # start_tls transfers the socket before its Future completes. On TLS
            # failure, Tornado 6.2 leaves the old IOStream detached (socket=None).
            if self.stream.socket is not None:
                self.stream.close()
            if self.video:
                self.video.close()
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            if self.backend:
                try:
                    for report in self.state.release():
                        await asyncio.wait_for(self.backend.write_message(report, binary=True), 2)
                except (websocket.WebSocketClosedError, asyncio.TimeoutError):
                    pass
                finally:
                    self.backend.close()
            self.nano.streams.discard(self.video)
            if self.nano.vnc_client is self:
                self.nano.vnc_client = None

    async def watch_backend(self):
        while await self.backend.read_message() is not None:
            pass
        raise EOFError('NanoKVM input disconnected')

    async def check_session(self):
        await self.nano.api('/api/auth/account', self.session)
        await self.backend.write_message(b'\x00', binary=True)

    async def keepalive(self):
        while True:
            await asyncio.sleep(10)
            await self.check_session()

    async def capture(self):
        while True:
            self.frame, self.frame_size = await asyncio.to_thread(self.video.read)
            self.nano.size = self.frame_size
            self.revision += 1
            self.changed.set()

    async def receive(self):
        while True:
            kind = (await self.read(1))[0]
            if kind == 0:  # SetPixelFormat (Tight JPEG is pixel-format independent)
                payload = await self.read(19)
                bpp, depth, _, true_colour = payload[3:7]
                if bpp not in (16, 32) or not true_colour or depth > bpp:
                    raise ValueError('Use 24-bit colour in bVNC')
            elif kind == 2:  # SetEncodings
                _, count = struct.unpack('>BH', await self.read(3))
                if count > 256:
                    raise ValueError('Too many encodings')
                self.encodings = set(struct.unpack('>' + 'i' * count, await self.read(4 * count)))
                if 7 not in self.encodings or not any(-32 <= e <= -23 for e in self.encodings):
                    raise ValueError('Tight with JPEG quality is required')
            elif kind == 3:  # FramebufferUpdateRequest
                incremental, x, y, w, h = struct.unpack('>BHHHH', await self.read(9))
                # Coalesce requests, retaining any outstanding full refresh.
                self.incremental = bool(incremental) if not self.requested.is_set() else self.incremental and bool(incremental)
                self.bounds = (x, y, w, h)
                self.requested.set()
            elif kind == 4:
                down, sym = struct.unpack('>B2xI', await self.read(7))
                if down not in (0, 1):
                    raise ValueError('Invalid key state')
                report = self.state.key(sym, bool(down))
                if report:
                    await self.backend.write_message(report, binary=True)
            elif kind == 5:
                mask, x, y = struct.unpack('>BHH', await self.read(5))
                await self.backend.write_message(
                    self.state.pointer(mask, x, y, self.width, self.height), binary=True)
            elif kind == 6:  # Clipboard is intentionally not typed into the host.
                length = struct.unpack('>3xI', await self.read(7))[0]
                if length > 65536:
                    raise ValueError('Clipboard too large')
                await self.read(length)
            else:
                raise ValueError('Unsupported RFB message')

    async def send_frames(self):
        last_revision = 0
        while True:
            await self.requested.wait()
            if 7 not in self.encodings:
                raise ValueError('Tight encoding required')
            while self.incremental and self.revision == last_revision:
                self.changed.clear()
                await self.changed.wait()
            frame, size, revision = self.frame, self.frame_size, self.revision
            self.requested.clear()
            resize = size != (self.width, self.height)
            if resize:
                if -223 not in self.encodings:
                    raise ValueError('Client cannot resize; reconnect')
                self.width, self.height = size
                # DesktopSize must be the last rectangle in an update. The client
                # requests the new full framebuffer after processing this update.
                await self.write(struct.pack('>BBHHHHHi', 0, 0, 1, 0, 0,
                                             self.width, self.height, -223))
                continue
            if self.bounds != (0, 0, self.width, self.height):
                raise ValueError('Full-frame updates required')
            header = struct.pack('>BBHHHHHi', 0, 0, 1, 0, 0, self.width, self.height, 7)
            await self.write(header + b'\x90' + compact_length(len(frame)) + frame)
            last_revision = revision
            self.sent_frames += 1
            self.sent_bytes += len(frame)
            await asyncio.sleep(1 / self.server.max_fps)


class VNCServer(tcpserver.TCPServer):
    def __init__(self, nano, tls, max_fps=20):
        super().__init__(max_buffer_size=131072)
        self.nano, self.tls, self.max_fps = nano, tls, max_fps
        self.clients = {}

    async def handle_stream(self, stream, address):
        if len(self.clients) >= 4:
            stream.close()
            return
        stream.set_nodelay(True)
        client = VNCConnection(self, stream)
        task = asyncio.current_task()
        self.clients[task] = client
        try:
            await client.run()
        finally:
            del self.clients[task]

    async def shutdown(self):
        self.stop()
        tasks = list(self.clients)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def server_tls(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # bVNC pins the leaf and rejects a multi-certificate server chain.
    # Copy only the PUBLIC certificate to a temporary file; never copy the key.
    with open(cert, 'rb') as source:
        chain = source.read(65536)
    end = b'-----END CERTIFICATE-----'
    if end not in chain:
        raise ValueError('Invalid certificate')
    leaf = chain.split(end, 1)[0] + end + b'\n'
    with tempfile.NamedTemporaryFile() as public_cert:
        public_cert.write(leaf)
        public_cert.flush()
        context.load_cert_chain(public_cert.name, key)
    return context


class Landing(web.RequestHandler):
    def get(self):
        self.set_header('Content-Type', 'text/html; charset=utf-8')
        self.finish('<!doctype html><title>PiKVM-compatible NanoKVM bridge</title>'
                    '<h1>NanoKVM → TouchKVM</h1><p>Use the PiKVM profile, HTTPS, '
                    'this port, your NanoKVM web login, and MJPEG mode (TouchKVM Pro). '
                    'WebRTC and the PiKVM web console are not implemented.</p>')


def application(nano):
    def log(handler):
        # Do not log query strings, credentials, cookies, bodies, or input data.
        LOG.info('%s %s %d', handler.request.method, handler.request.path, handler.get_status())
    return web.Application([
        (r'/', Landing), (r'/api/ws', Input), (r'/api/(.*)', API),
        (r'/streamer/(stream|snapshot)', Video), (r'/stream', Video), (r'/streamer/?', Video),
    ], nano=nano, log_function=log, websocket_max_message_size=8192,
        websocket_ping_interval=20, websocket_ping_timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--vnc-port', type=int, default=5900, help='VNC port; 0 disables VNC')
    parser.add_argument('--vnc-fps', type=int, default=20, help='Maximum VNC updates/second (1-60)')
    parser.add_argument('--cert', default='/etc/kvm/server.crt')
    parser.add_argument('--key', default='/etc/kvm/server.key')
    parser.add_argument('--upstream', default='https://127.0.0.1')
    parser.add_argument('--upstream-ca')
    args = parser.parse_args()
    if not 0 <= args.vnc_port <= 65535 or not 1 <= args.vnc_fps <= 60:
        parser.error('VNC port must be 0-65535 and VNC FPS must be 1-60')
    if args.vnc_port == args.port:
        parser.error('HTTPS and VNC require different ports')
    target = urlsplit(args.upstream)
    local = target.hostname in ('127.0.0.1', '::1', 'localhost')
    if (target.scheme not in ('http', 'https') or not target.hostname or target.username
            or target.password or target.path not in ('', '/') or target.query or target.fragment
            or (target.scheme == 'http' and not local)):
        parser.error('Use an HTTPS upstream origin (HTTP is allowed only on loopback)')
    upstream_tls = (ssl._create_unverified_context() if local and not args.upstream_ca
                    else ssl.create_default_context(cafile=args.upstream_ca))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)

    async def serve():
        nano = NanoKVM(args.upstream, upstream_tls)
        if local:
            nano.load_screen('/kvmapp/kvm')
        server = httpserver.HTTPServer(application(nano), ssl_options=tls, max_body_size=65536)
        server.listen(args.port, args.listen)
        LOG.info('TouchKVM MJPEG bridge %s listening on HTTPS port %d', VERSION, args.port)
        vnc = None
        if args.vnc_port:
            vnc = VNCServer(nano, server_tls(args.cert, args.key), args.vnc_fps)
            vnc.listen(args.vnc_port, args.listen)
            LOG.info('VNC listening on port %d (VeNCrypt X509Plain)', args.vnc_port)
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        await stop.wait()
        server.stop()
        if vnc:
            await vnc.shutdown()
        if nano.controller:
            await nano.controller.close()
        for source in list(nano.streams):
            source.close()
        await server.close_all_connections()
        nano.http.close()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s: %(message)s')
    asyncio.run(serve())


if __name__ == '__main__':
    main()
