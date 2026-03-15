# VM Deployment with VS Code Remote-SSH

This guide is the recommended workflow for deploying TransactiWar to the course-provided VM.

## 1. Connect to the VM

Install these VS Code extensions on your local machine:

- `Remote - SSH`
- `Remote Explorer` (optional)

Add this host entry to your local SSH config:

```sshconfig
Host transactiwar-vm
    HostName 10.96.1.242
    User ubuntu
```

Connect from VS Code with `Remote-SSH: Connect to Host...` and select `transactiwar-vm`.

On first login:

```bash
passwd
```

Rotate the password immediately, then share the new password with your teammates as instructed by the course staff.

## 2. Prepare the VM

Verify the VM has:

- `git`
- `docker`
- Docker Compose plugin

Clone the repository onto the VM and work from the cloned repo. Keep Git as the source of truth for deployment updates.

## 3. Configure `docker/.env` for VM access

Create the runtime env file:

```bash
cp docker/.env.example docker/.env
```

Set strong VM-specific secrets:

- `MYSQL_ROOT_PASSWORD`
- `MYSQL_PASSWORD`
- `SESSION_SECRET`

Use VM-accessible network and TLS settings:

```dotenv
APP_BIND=0.0.0.0
CSRF_ALLOWED_ORIGIN=https://10.96.1.242
TLS_CERT_CN=10.96.1.242
TLS_CERT_SAN=IP:10.96.1.242
```

The deployment uses fixed host ports `80` and `443`. Only update `CSRF_ALLOWED_ORIGIN` and TLS host/IP values to match the VM.

## 4. Regenerate TLS certs for the VM

The app container can generate a self-signed certificate automatically, but it must not reuse a stale `localhost` certificate.

Before first VM startup:

```bash
rm -f docker/certs/server.crt docker/certs/server.key
```

Those files are gitignored, so removing them on the VM is safe.

## 5. Start the stack

Run:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
docker compose --env-file docker/.env -f docker/docker-compose.yml ps -a
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --no-color setup
```

Expected result:

- `db` is healthy
- `setup` exited `0`
- `app` is up

## 6. Verify reachability

From the VM:

```bash
curl -kisS https://127.0.0.1/login.php | sed -n '1,20p'
```

From another machine on the same network/VPN:

```bash
curl -kisS https://10.96.1.242/login.php | sed -n '1,20p'
```

Then test in a browser from a teammate's machine:

- register
- login
- profile edit
- avatar upload
- user search
- transfer
- transaction history
- logout

## 7. Operating model after deployment

- Use Git pulls on the VM for normal updates.
- Use VS Code Remote-SSH for log inspection and emergency fixes.
- Do not use ad hoc drag-and-drop as the primary deployment process.
