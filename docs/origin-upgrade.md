# Making the whole path post-quantum

My sites sit behind Cloudflare, so there are two TLS connections per request:

```
browser ──TLS──▶ Cloudflare edge ──TLS──▶ my VPS (Nginx)
         ML-KEM already            classical until the origin is upgraded
```

Cloudflare negotiates X25519MLKEM768 with browsers on its own, and it offers ML-KEM to origins too.
The origin only takes it if its TLS library supports it, so the second hop stays classical until
Nginx runs on OpenSSL 3.5 or newer.

## 1. Edge: drop TLS 1.0 and 1.1 (each zone)

Cloudflare dashboard → the zone → SSL/TLS → Edge Certificates → **Minimum TLS Version: TLS 1.2**.

Then check:

```bash
pqready -f data/mine.txt          # expect A+ on every site
```

## 2. Origin: check what Nginx is linked against

```bash
nginx -V 2>&1 | grep -o 'OpenSSL [0-9.]*'
```

- **3.5 or newer** (Ubuntu 26.04, Debian 13, Alpine 3.22, the `nginx:alpine` image): go to step 3.
- **Older** (Ubuntu 24.04 ships 3.0): either move the site to the `nginx:alpine` container, or
  upgrade the OS. Don't hand-compile OpenSSL on a production box.

## 3. Origin: one line

In the `server` (or `http`) block:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 4. Verify the origin hop directly

Skip Cloudflare and dial the VPS, keeping the real hostname as SNI:

```bash
pqready omaribrahim.me --connect <VPS_IP>
```

Expect `browsers X25519MLKEM768`. If the origin only allows Cloudflare's IP ranges, run this from the
VPS itself with `--connect 127.0.0.1`.

## 5. Keep it from regressing

Add to the deploy workflow:

```yaml
- run: pip install pqready && pqready -f data/mine.txt --fail-under A
```
