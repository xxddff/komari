
# Komari 
![Badge](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Fkomari-monitor%2Fkomari&label=&icon=github&color=%23a370f7&message=&style=flat&tz=UTC)

![komari](https://socialify.git.ci/komari-monitor/komari/image?description=1&font=Inter&forks=1&issues=1&language=1&logo=https%3A%2F%2Fraw.githubusercontent.com%2Fkomari-monitor%2Fkomari-web%2Fd54ce1288df41ead08aa19f8700186e68028a889%2Fpublic%2Ffavicon.png&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto)

[简体中文](./docs/README_zh.md) | [繁體中文](./docs/README_zh-TW.md) | [日本語](./docs/README_ja.md)

Komari is a lightweight, self-hosted server monitoring tool designed to provide a simple and efficient solution for monitoring server performance. It supports viewing server status through a web interface and collects data through a lightweight agent.

[Documentation](https://komari-document.pages.dev/) | [Telegram Group](https://t.me/komari_monitor)

## Features
- **Lightweight and Efficient**: Low resource consumption, suitable for servers of all sizes.
- **Self-hosted**: Complete control over data privacy, easy to deploy.
- **Web Interface**: Intuitive monitoring dashboard, easy to use.

## Quick Start

### 0. One-click Deployment with Cloud Hosting
- Rainyun - CNY 4.5/month 

[![](https://rainyun-apps.cn-nb1.rains3.com/materials/deploy-on-rainyun-cn.svg)](https://app.rainyun.com/apps/rca/store/6780/NzYxNzAz_) 

- Claw Run - USD 1.5/month

[![](https://raw.githubusercontent.com/ClawCloud/Run-Template/refs/heads/main/Run-on-ClawCloud.svg)](https://template.run.claw.cloud/?openapp=system-fastdeploy%3FtemplateName%3Dkomari)

### 1. Use the One-click Install Script
Suitable for distributions using systemd (Ubuntu, Debian...).
```bash
curl -fsSL https://raw.githubusercontent.com/komari-monitor/komari/main/install-komari.sh -o install-komari.sh
chmod +x install-komari.sh
sudo ./install-komari.sh
```

### 2. Docker Deployment
1. Create a data directory:
   ```bash
   mkdir -p ./data
   ```
2. Run the Docker container:
   ```bash
   docker run -d \
     -p 25774:25774 \
     -v $(pwd)/data:/app/data \
     --name komari \
     ghcr.io/komari-monitor/komari:latest
   ```
3. View the default username and password:
   ```bash
   docker logs komari
   ```
4. Access `http://<your_server_ip>:25774` in your browser.

> [!NOTE]
> You can also customize the initial username and password through the environment variables `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

### 3. Binary File Deployment
1. Visit Komari's [GitHub Release page](https://github.com/komari-monitor/komari/releases) to download the latest binary for your operating system.
2. Run Komari:
   ```bash
   ./komari server -l 0.0.0.0:25774
   ```
3. Access `http://<your_server_ip>:25774` in your browser. The default port is `25774`.
4. The default username and password can be found in the startup logs or set via the environment variables `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

> [!NOTE]
> Ensure the binary has execute permissions (`chmod +x komari`). Data will be saved in the `data` folder in the running directory.

## Cloudflare Access Integration

Komari supports automatic login through Cloudflare Access. When enabled, users authenticated by Cloudflare Access will be automatically logged into Komari without additional clicks.

### Configuration

Set the following environment variables to enable Cloudflare Access integration:

```bash
# Enable Cloudflare Access integration
KOMARI_CF_ACCESS_ENABLED=true

# Set the admin email that should be automatically logged in
# This email must match the email authenticated by Cloudflare Access
KOMARI_CF_ACCESS_ADMIN_EMAIL=admin@yourdomain.com

# Optional: Set trusted Cloudflare Access domain for additional security
KOMARI_CF_ACCESS_TRUSTED_DOMAIN=your-team-name.cloudflareaccess.com
```

### How it works

1. User accesses Komari through Cloudflare Access
2. Cloudflare Access authenticates the user and adds headers to the request
3. Komari reads the `Cf-Access-Authenticated-User-Email` header
4. If the email matches `KOMARI_CF_ACCESS_ADMIN_EMAIL`, user is automatically logged in
5. A session is created and the user gains admin access

### Security Notes

- Only the email specified in `KOMARI_CF_ACCESS_ADMIN_EMAIL` will be granted access
- The integration respects existing sessions and won't interfere with other authentication methods
- All automatic logins are logged in the audit log


### Manual Build

#### Dependencies

- Go 1.18+ and Node.js 20+ (for manual build)

1. Build the frontend static files:
   ```bash
   git clone https://github.com/komari-monitor/komari-web
   cd komari-web
   npm install
   npm run build
   ```
2. Build the backend:
   ```bash
   git clone https://github.com/komari-monitor/komari
   cd komari
   ```
   Copy the static files generated in step 1 to the `/public/dist` folder in the root of the `komari` project.
   ```bash 
   go build -o komari
   ```
4. Run:
   ```bash
   ./komari server -l 0.0.0.0:25774
   ```
   The default listening port is `25774`. Access `http://localhost:25774`.

## Frontend Development Guide
[Komari Theme Development Guide | Komari](https://komari-document.pages.dev/dev/theme.html)

[Translate Komari on Crowdin](https://crowdin.com/project/komari/invite?h=cd051bf172c9a9f7f1360e87ffb521692507706)

## Client Agent Development Guide
[Komari Agent Information Reporting and Event Handling Documentation](https://komari-document.pages.dev/dev/agent.html)

## Contributing
Issues and Pull Requests are welcome!

## Acknowledgements
 - [DreamCloud - 极高性价比解锁直连亚太高防](https://as211392.com/)
 - Thanks to myself for being so idle
 - All the developers who submitted PRs and created themes

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=komari-monitor/komari&type=Date)](https://www.star-history.com/#komari-monitor/komari&Date)

