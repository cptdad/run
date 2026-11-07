# External SOCKS proxy mode

By default Rún reaches its relay (a Tor onion service) through a Tor client embedded in the app. This mode replaces that: you point the app at a SOCKS5 proxy you run, and the app sends all relay traffic there. The embedded Tor is not started.

> **Android only for now.** The setting is hidden in the iOS app, and any value an earlier iOS build stored is cleared at launch. The iOS sections below describe the implementation, which is kept for later.

## What it does

Settings -> External proxy: a host and a port.

- The host must be an IP literal: loopback (`127.x.x.x`, `::1`) or a private LAN address (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`). Hostnames are rejected.
- The change applies at the next launch.
- While it is on, the embedded Tor is never started. Relay requests go through the proxy using SOCKS5h: the `.onion` name is sent to the proxy unresolved, and the app does no DNS lookup for it.
- If the proxy is unreachable the app fails closed. Messaging stops. It does not fall back to the embedded Tor or to a direct connection.
- Connect telemetry is not sent in this mode.
- A wipe clears the setting.
- LAN hosts show a warning. The hop from the phone to the proxy is plain TCP on your LAN. Whoever can see your LAN sees that hop. The relay requests on it are plain HTTP, but the message bodies are the app's own end-to-end-encrypted blobs. An observer on that hop sees request metadata (method, path, sizes, timing) and encrypted bodies. Onward encryption exists only if the proxy is Tor. The proxy is trusted to be Tor.

Push notifications are separate. FCM and UnifiedPush on Android, and APNs on iOS, are OS channels that run in other processes (Google Play services, the UnifiedPush distributor, Apple's `apsd`). They do not go through this proxy and this setting does not affect them.

## What it is for

- Checking what the app sends. You can put a logger on the proxy path and read every relay request.
- Using your own Tor (your own version, config, bridges, or a Tor you already trust) instead of the one bundled in the app.

## What it does not prove

- That the binary you run matches the source. This mode checks traffic, not build provenance.
- What is inside the encrypted blobs. You see their size and timing, not their content. A logger cannot tell you that a blob contains only the message.
- Covert channels inside encrypted payloads. Anything the app could encode into a blob would look like a blob.
- The push side channel. Google Play services or APNs may learn that a notification was sent and when. Those processes are outside the app and outside the proxy.
- That the proxy is Tor. The app only knows it is speaking SOCKS5.

## Setup

Use placeholders below: `<proxy-ip>` is the address of the machine running the proxy, `<lan-cidr>` is your LAN range (for example a /24 you own).

### Android with Orbot (same phone)

1. Install Orbot and start it. Wait until it reports connected.
2. Check in Orbot's settings that its SOCKS port is `9050` on `127.0.0.1`. Orbot's defaults have changed between versions, so verify in the app.
3. In Rún: Settings -> External proxy -> host `127.0.0.1`, port `9050`.
4. Restart Rún. Orbot must be running before the app starts.

Loopback hosts show no LAN warning.

### Android or iOS with a tor daemon on a LAN box

On the Mac or Linux box, in `torrc`:

```
SocksPort <proxy-ip>:9050
SocksPolicy accept <lan-cidr>
SocksPolicy reject *
```

Tor has no `SocksPort` on loopback once you bind only `<proxy-ip>`. If you also want `127.0.0.1:9050` (for example for the logging chain below), add `SocksPort 127.0.0.1:9050` and `SocksPolicy accept 127.0.0.1` before the `reject` line, because the policy applies to every SocksPort. Check the file with `tor --verify-config -f <path-to-torrc>` and restart tor. With Homebrew on a Mac the file is usually `/opt/homebrew/etc/tor/torrc`.

Binding to the specific LAN address is safer than `0.0.0.0`. If you must use `SocksPort 0.0.0.0:9050`, keep the `SocksPolicy` lines and also block port 9050 at the host firewall for anything outside the LAN. An open SOCKS port lets anyone who reaches it use your Tor client and your connection. Do not expose it to the internet or to guest Wi-Fi.

Then in Rún: Settings -> External proxy -> host `<proxy-ip>`, port `9050`, and restart the app.

### iOS

iOS has no practical way for another app to run a SOCKS server on the same device, so use a tor daemon on a Mac or Linux box on the LAN, as above. On first use iOS shows a Local Network permission prompt for Rún. Allow it, or the app cannot reach the proxy and (by design) stays offline. Loopback does not work on iOS in practice, because there is nothing on the phone to listen.

### Seeing the requests: a logging chain

You want: app -> logging SOCKS proxy -> Tor (`127.0.0.1:9050`) -> relay.

Be careful with off-the-shelf tools. As far as I know:

- `microsocks` is a small SOCKS5 server that connects out directly. It does not chain to an upstream SOCKS proxy. Verify with its docs before relying on it.
- `mitmproxy --mode socks5` can act as a SOCKS5 proxy, but it cannot use an upstream SOCKS proxy for its outbound connections (its upstream mode is for HTTP proxies). Verify with the mitmproxy docs for your version. A setup that works: run mitmproxy's SOCKS mode on a box whose own outbound traffic is forced through Tor by a transparent redirect, and resolving a `.onion` there needs that redirect to handle Tor's onion mapping. That is more work than the option below.

The simplest correct option is a small forwarder that speaks SOCKS5 to the app, logs the CONNECT target, request lines and byte counts, and chains to Tor with the name still unresolved. The relay protocol is plain HTTP inside the onion (no TLS), so request lines are readable. A minimal Python 3 version (no authentication, CONNECT only, treat it as a sketch):

```python
import asyncio, ipaddress, sys, time

TOR = ("127.0.0.1", 9050)
METHODS = (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"PATC", b"OPTI")

def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)

async def pipe(r, w, tag, counter):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            counter[tag] += len(d)
            if tag == "up" and d[:4] in METHODS:
                log("REQ", d.split(b"\r\n", 1)[0][:200].decode("latin1"))
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass

async def handle(cr, cw):
    try:
        h = await cr.readexactly(2)
        await cr.readexactly(h[1])           # client auth methods
        cw.write(b"\x05\x00"); await cw.drain()
        req = await cr.readexactly(4)        # VER CMD RSV ATYP
        atyp = req[3]
        if atyp == 1: addr = await cr.readexactly(4)
        elif atyp == 4: addr = await cr.readexactly(16)
        elif atyp == 3:
            n = await cr.readexactly(1); addr = n + await cr.readexactly(n[0])
        else: return
        port = await cr.readexactly(2)
        if req[1] != 1:                      # CONNECT only
            cw.write(b"\x05\x07\x00\x01" + bytes(6)); return
        name = addr[1:].decode("latin1") if atyp == 3 else str(ipaddress.ip_address(addr))
        log("CONNECT", name, int.from_bytes(port, "big"))
        tr, tw = await asyncio.open_connection(*TOR)
        tw.write(b"\x05\x01\x00"); await tw.drain()
        if await tr.readexactly(2) != b"\x05\x00":
            return
        tw.write(req + addr + port); await tw.drain()  # name stays unresolved
        rep = await tr.readexactly(4)
        if rep[3] == 1: tail = await tr.readexactly(6)
        elif rep[3] == 4: tail = await tr.readexactly(18)
        else:
            n = await tr.readexactly(1); tail = n + await tr.readexactly(n[0] + 2)
        cw.write(rep + tail); await cw.drain()
        if rep[1] != 0:
            log("TOR REFUSED", rep[1]); return
        c = {"up": 0, "down": 0}
        await asyncio.gather(pipe(cr, tw, "up", c), pipe(tr, cw, "down", c))
        log("CLOSE", name, "up", c["up"], "down", c["down"])
    except Exception as e:
        log("ERR", repr(e))
    finally:
        cw.close()

async def main(bind, port):
    s = await asyncio.start_server(handle, bind, port)
    async with s:
        await s.serve_forever()

asyncio.run(main(sys.argv[1], int(sys.argv[2])))
```

Run `python3 -I socks_log.py <proxy-ip> 9051` (use `127.0.0.1` to keep it local) and set Rún's proxy to `<proxy-ip>:9051`. This is a debugging tool: it logs only the first line of a request chunk, and a request spread over several reads may be partly missed. A client that does not speak SOCKS5 is dropped and shows as an `ERR` line. Tested against Tor 0.4.9 with `curl --socks5-hostname 127.0.0.1:9051 http://<onion>/`: CONNECT target, request lines (GET and POST), byte counts and concurrent connections all log correctly. Use a packet capture on the proxy box (loopback or LAN interface, port 9051) if you need exact bytes.

Treat the log as sensitive. The relay's capability tokens travel in request headers, not in paths, so a logger that records only request lines will miss them, but a packet capture or a full-header logger will see them. Do not share it, and rotate or delete it afterwards.

## Verifying the embedded Tor is not used

Do these with the setting on and the app freshly relaunched.

### Android

Find the app's UID (the package id is `com.vg.run`):

```
adb shell pm list packages -U | grep -i com.vg.run
```

Network view, per app:

- NetGuard, or on GrapheneOS the per-app "Network" permission: allow Rún only to `<proxy-ip>:9050` (or `127.0.0.1:9050` with Orbot). If you are using Orbot on the same phone, use per-UID rules, since Orbot's traffic is a different UID. With these rules, an app that still tries to start its own Tor will show blocked connections in the NetGuard log. Expect: no allowed or attempted connections from Rún's UID other than to the proxy host:port and loopback.

Socket view (the `uid` column is the 8th field; addresses are little-endian hex, state `01` is established):

```
adb shell "awk '\$8==<uid>' /proc/net/tcp /proc/net/tcp6"
```

On some Android builds `/proc/net/tcp` is not readable from the shell. If so, use NetGuard's log instead. Expect only the proxy address (and loopback) among Rún's sockets. A listener on `127.0.0.1` owned by Rún's UID would be a Tor SOCKS or control port, which should not exist in this mode.

Process view: there should be no Tor process under Rún's UID.

```
adb shell "ps -A -o USER,PID,PPID,NAME,ARGS | grep -i tor"
adb shell "ps -A -o USER,PID,PPID,NAME,ARGS | grep u0_a<N>"
```

(`u0_a<N>` is Rún's user name from the UID: UID `10000 + N`.) The first command may also match Orbot's own tor, which runs under Orbot's UID, not Rún's.

### iOS

iOS exposes no per-app socket view, so check from the network:

1. Put the phone on a Wi-Fi network whose router or firewall blocks all outbound traffic from the phone except to `<proxy-ip>:9050`. Cellular must be off for Rún, or the phone off cellular, so traffic cannot bypass the firewall.
2. Watch the firewall log while you launch the app and send a message.
3. Expect: the app works only via the proxy, and no other destinations from the phone (other than Apple's own services, below). If the proxy is stopped, the app must go offline and not retry through other routes.

APNs push is separate. Apple's `apsd` process makes its own connections to Apple. You can allow or block those independently, but blocking them disables notifications.

## Residual risks

- The app's push channels (FCM, UnifiedPush, APNs) bypass the proxy and reveal timing to the push providers.
- On a LAN proxy, the phone-to-proxy hop is unencrypted. Use loopback or a network you control.
- An exposed SOCKS port is an open proxy for anyone who can reach it.
- The proxy sees every request and its timing and is trusted to be Tor. If it is not, the proxy operator sees the relay traffic metadata and can reach the relay.
- A logging proxy's log may contain capability tokens (they are sent in request headers).
- Verification covers traffic only. It does not cover the app binary, blob contents, or covert channels within encrypted payloads.
- Failing closed means messaging stops whenever the proxy is down. It does not stop when the phone leaves your network: the app keeps dialling the configured IP on any network and trusts whatever answers. On a foreign network, anyone who controls or impersonates that address receives the capability tokens (they can delete or take over your conversation inboxes, but cannot read messages).
- The proxy must be trusted. The HTTP to the relay is plaintext inside the tunnel, so the proxy (and, if it is not Tor, everything beyond it) sees the requests and the tokens.
- On Android, a loopback proxy (127.0.0.1 or ::1) can be squatted: while the proxy app (for example Orbot) is not running, any other app on the phone can listen on its port and receive the same tokens. Set the proxy app to a non-default, random port and keep it running.
- When you leave your network, turn the mode off (Settings -> External proxy, then restart the app).
