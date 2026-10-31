# Sipeed NanoKVM phone app bridge

**Goal: make the Sipeed NanoKVM work with phone apps—specifically TouchKVM and bVNC.**

This single Python script runs on an original [NanoKVM by Sipeed](https://github.com/sipeed/NanoKVM)
and translates the protocols
those apps understand into NanoKVM's existing video, keyboard, mouse and power APIs.
You can access the attached computer's HDMI output and USB input, including its
BIOS and boot screens, without installing software on that computer.

```text
TouchKVM ── PiKVM API / HTTPS :8443 ──┐
                                    ├── bridge.py ── NanoKVM ── HDMI / USB ── computer
bVNC     ── encrypted VNC :5900 ──────┘
```

Video uses NanoKVM's MJPEG capture and is forwarded without decoding or re-encoding.
The bridge reuses your NanoKVM web account. There is no separate bridge password.

| Phone app | Connection | Status |
| --- | --- | --- |
| **bVNC Free** | VeNCrypt + Tight/JPEG | Verified with bVNC 6.4.9 and live 1920×1080 NanoKVM video |
| **TouchKVM** | PiKVM profile + MJPEG | API/protocol tests pass; end-to-end app compatibility remains unverified |

**TouchKVM's MJPEG mode requires Pro.** Its free WebRTC mode is not implemented.
See [TouchKVM's feature requirements](https://arisparty.org/touchkvm/support/).
bVNC provides a free, open-source option; get it from the
[upstream project](https://github.com/iiordanov/remote-desktop-clients).
This is an experimental translation layer, not a complete PiKVM implementation.

## Install on NanoKVM

Requires Python **3.9+**, **Tornado 6.2–6.x** and the `openssl` executable.
The tested original NanoKVM already includes these dependencies. If needed,
install the Python dependency with `python3 -m pip install -r requirements.txt`.
NanoKVM's web login must be enabled.

Copy the script from your computer:

```sh
scp bridge.py root@nanokvm:/root/nanokvm-pikvm-bridge.py
ssh root@nanokvm
```

Run the remaining installation commands on NanoKVM. Replace `nanokvm` with its
IP address when that hostname does not resolve.

### If NanoKVM already has HTTPS certificates

The defaults use NanoKVM's HTTPS backend and existing certificate files:

```sh
python3 /root/nanokvm-pikvm-bridge.py
```

Default upstream: `https://127.0.0.1`. Default certificate/key:
`/etc/kvm/server.crt` and `/etc/kvm/server.key`.
If your files are elsewhere, pass `--cert /path/server.crt --key /path/server.key`.

### If NanoKVM uses HTTP and has no certificates

You do **not** need to set up HTTPS for NanoKVM's own web UI. Generate a certificate
for the bridge, and let it talk to NanoKVM over HTTP on loopback. Phone connections
still use HTTPS or encrypted VNC.

Set `NANO_IP` to your NanoKVM's actual LAN address before running this example:

```sh
NANO_IP=192.168.1.50
umask 077
mkdir -p /root/.nanokvm-bridge
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout /root/.nanokvm-bridge/server.key \
  -out /root/.nanokvm-bridge/server.crt \
  -subj '/CN=nanokvm' \
  -addext "subjectAltName=DNS:nanokvm,IP:$NANO_IP"

python3 /root/nanokvm-pikvm-bridge.py \
  --upstream http://127.0.0.1 \
  --cert /root/.nanokvm-bridge/server.crt \
  --key /root/.nanokvm-bridge/server.key
```

These commands create a self-signed certificate valid for one year. If NanoKVM's
HTTP server uses another port, include it in `--upstream`, for example
`http://127.0.0.1:80`. Do not overwrite an existing certificate/key when following
this setup. Renew the certificate before it expires and update the app's trust
settings when it changes.

bVNC asks you to accept the certificate on first connection. Compare the displayed
SHA-256 fingerprint with this command, run over your trusted SSH connection:

```sh
openssl x509 -in /root/.nanokvm-bridge/server.crt -noout -fingerprint -sha256
```

Use `/etc/kvm/server.crt` instead if using NanoKVM's existing certificate.
TouchKVM must also trust the certificate through its supported settings; otherwise
use a certificate issued by a CA the app trusts. The bridge never sends phone
credentials over an unencrypted connection.

### Start automatically

Stop the foreground script with Ctrl+C. From your computer, install the optional
Buildroot/BusyBox service:

```sh
scp S99nanokvm-touch root@nanokvm:/etc/init.d/S99nanokvm-touch
ssh root@nanokvm 'chmod 700 /root/nanokvm-pikvm-bridge.py /etc/init.d/S99nanokvm-touch'
```

For the default HTTPS setup, no configuration file is needed. For the **HTTP
backend / generated certificate** setup, create this file on NanoKVM:

```sh
mkdir -p /etc/default
umask 077
cat > /etc/default/nanokvm-touch <<'CONFIG'
UPSTREAM=http://127.0.0.1
CERT=/root/.nanokvm-bridge/server.crt
KEY=/root/.nanokvm-bridge/server.key
CONFIG
```

The optional file is read as shell configuration. Keep it owned by root; put only
connection settings in it, not web login credentials. It can also set `PORT=8443`,
`VNC_PORT=5900` and `VNC_FPS=20`. `VNC_PORT=0` disables the VNC listener.

Start or manage both interfaces with the same service:

```sh
/etc/init.d/S99nanokvm-touch start
/etc/init.d/S99nanokvm-touch status
/etc/init.d/S99nanokvm-touch restart
/etc/init.d/S99nanokvm-touch stop
```

The existing NanoKVM web UI keeps its own port. Stop any older standalone bridge
service before starting this one, particularly `S99nanokvm-vnc` from older versions.
Firmware updates may remove custom startup scripts.

## Connect from bVNC

Create a **new** connection:

| Setting | Value |
| --- | --- |
| Connection type | **Secure VNC over VeNCrypt** |
| VNC server | NanoKVM's hostname or IP, without `https://` |
| Port | **5900** |
| VNC username/password | Your **NanoKVM web** login |
| Color mode | **24-bit color** |
| Encoding | **Tight**, with JPEG enabled; bVNC's default works |
| Fullscreen bitmap | **On** if automatic mode requests only part of the screen |

Verify and accept the certificate fingerprint when prompted. A profile reused
from a different server can retain the old certificate and fail with
`certificate_unknown`; create a fresh profile for this NanoKVM.
In bVNC 6.4.9, launching a saved connection without a saved password sent an empty
password during testing. Enter the web password and enable **Save password** for
that connection. Stored app credentials are managed by bVNC, not by this bridge.

VNC provides video and keyboard/mouse control. Use TouchKVM or the NanoKVM web UI
for ATX power controls. Connect while NanoKVM has an active HDMI signal; if capture
is unavailable, retry when the signal returns.

## Connect from TouchKVM

| Setting | Value |
| --- | --- |
| Device/vendor | **PiKVM** |
| Host | NanoKVM's hostname or IP |
| Port | **8443** |
| HTTPS | **Enabled** |
| Username/password | Your **NanoKVM web** login |
| Stream mode | **MJPEG** (requires Pro) |

If a complete URL is requested, use `https://<nanokvm-address>:8443`.
WebRTC and Web UI modes are not supported. The bridge's root page is a setup
notice, not a PiKVM web console. Do not purchase Pro solely on the assumption
that this experimental adapter already works with your app version.

For either app, the phone must be able to reach NanoKVM through the LAN or an
existing VPN. This project does not configure remote network access.

## What the layer translates

| Capability | Translation |
| --- | --- |
| Login | PiKVM cookie/Basic/header auth or VNC X509Plain → NanoKVM web authentication |
| Video | NanoKVM MJPEG → PiKVM MJPEG/snapshots or VNC Tight/JPEG rectangles |
| Keyboard/mouse | PiKVM HTTP/WebSocket events or VNC keysyms/pointer events → NanoKVM USB HID |
| ATX | PiKVM power/click API → NanoKVM GPIO button pulses and LED state |
| Capture controls | PiKVM quality/FPS/resolution/reset API → NanoKVM capture APIs |

VNC uses **RFB 3.8, VeNCrypt 0.2 and X509Plain**, with TLS 1.2+. It requires
Tight/JPEG and full-frame update requests; ordinary password-only VNC clients,
8-bit colour and clients without JPEG are unsupported. Resolution changes use
DesktopSize. VNC presents the leaf certificate for bVNC compatibility; HTTPS
presents the full configured chain.

Input supports a US keyboard layout, common modifiers/navigation keys, F1–F24,
numpad keys, three mouse buttons and vertical scrolling. Six non-modifier keys
can be held simultaneously. Held inputs are released when their session ends.
VNC clipboard and unsupported Unicode keysyms are ignored. PiKVM paste supports
up to 400 characters through NanoKVM's US-layout paste API.

ATX requires the appropriate cable. Normal on/off requests use a short press,
based on the power LED. Explicit hard-off uses a five-second button hold.
Capture quality maps to 50/60/80/100, FPS to 10–60 (a request of `0` means 60), and
resolution to 640×480, 800×600, 1280×720 or 1920×1080. These settings affect all
NanoKVM viewers. Capture reset does not reset the attached computer.

## Limits and troubleshooting

- Tested hardware/software: **original NanoKVM**, application **2.5.2**, image
  **v1.4.2**, Python **3.11.6** and Tornado **6.2**. Other NanoKVM models and firmware
  versions are unverified.
- Two video streams in total, with one input session across both interfaces.
  Disconnect the active input session before switching apps. HTTP-only input
  expires after roughly 15–25 seconds idle. Other direct NanoKVM clients can
  still interleave input.
- Maximum JPEG size: 4 MiB minus one byte; maximum dimensions: 2048×2160.
  VNC defaults to 20 updates/second. Set `--vnc-fps 1..60` to change that limit.
- No WebRTC/Janus, audio, ISO/media management, general GPIO controls, horizontal
  scrolling, mouse jiggler or USB mode switching. Unsupported API operations
  return errors rather than reporting success.
- Capture parameters initialize from local NanoKVM settings and track changes
  made through this bridge. Changes made in NanoKVM's web UI cannot reliably be
  reflected because its API has no capture-settings GET endpoint. Actual video
  dimensions come from JPEG headers. FPS is a requested limit, not a measurement.
- Credentials/cookies stay in bridge memory. Bridge cookies expire after 12 hours
  or restart; cached NanoKVM logins last five minutes. Active sessions recheck
  authorization every ten seconds. Logs exclude credentials, query strings and
  typed input.

Read service logs with `cat /tmp/nanokvm-touch.log`; they reset at service start.
A login failure refers to the **web** account, not the SSH account. HTTP 501 means
an unsupported PiKVM feature. WebRTC/Janus attempts mean MJPEG is not selected.
A certificate error may require trusting the correct certificate or replacing a
profile that pins an old one.

A bridge hosted on another computer must use an HTTPS upstream with a trusted CA:

```sh
python3 bridge.py --upstream https://nanokvm \
  --upstream-ca /path/to/nanokvm-ca.crt \
  --cert /path/to/bridge.crt --key /path/to/bridge.key
```

Plain HTTP upstreams are allowed only on loopback. Upstream certificate checking
is skipped only for loopback without an explicit CA. Phone-facing connections
always require TLS. Use `--vnc-port 0` to run only the TouchKVM interface.

Uninstall the service and script on NanoKVM:

```sh
/etc/init.d/S99nanokvm-touch stop
rm /etc/init.d/S99nanokvm-touch /root/nanokvm-pikvm-bridge.py
```

Remove any bridge-only configuration/certificates separately if no longer needed;
do not remove certificates used by NanoKVM's own web server.

## Validation

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

**43 automated tests** cover authentication, TLS rejection, authorization revocation,
video framing/resize, keyboard/mouse translation and cleanup, ATX/capture mapping,
and coexistence of the two protocols. Tests pass on Python 3.13 / Tornado 6.6 and
on NanoKVM's Python 3.11 / Tornado 6.2. Tests use a simulated backend and do not
operate the attached computer.

bVNC Free **6.4.9** was verified with live **1920×1080** NanoKVM video. Keyboard and
mouse delivery were verified against the test backend. Live PiKVM API checks
verified authentication, metadata, JPEG video and the idle input WebSocket.
TouchKVM app compatibility remains unverified.

## References

Protocol references: [PiKVM API](https://docs.pikvm.org/api/),
[KVMD](https://github.com/pikvm/kvmd),
[NanoKVM](https://github.com/sipeed/NanoKVM/tree/2.5.2), and
[the RFB specification](https://github.com/rfbproto/rfbproto).

## License

Open to use under the [MIT License](LICENSE).
