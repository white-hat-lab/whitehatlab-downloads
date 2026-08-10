# White Hat Labs DAST Installation

This guide is for the legacy `WhiteHatLabs-DAST-v1.2` package. It does not contain the current private-source fixes; see [CURRENT_SCANNER_RELEASE_STATUS.md](CURRENT_SCANNER_RELEASE_STATUS.md).

## Downloads

Download the retained legacy packaged app from:

https://github.com/white-hat-lab/whitehatlab-downloads/releases/tag/v1.2-dast

Use:

- `WhiteHatLabs-DAST-v1.2-Mac.zip` for macOS
- `WhiteHatLabs-DAST-v1.2.exe` for Windows

The public download contains packaged app files only. Source code is private.

## macOS Setup

1. Download `WhiteHatLabs-DAST-v1.2-Mac.zip`.
2. Unzip it.
3. Open Terminal in the unzipped folder.
4. Remove macOS quarantine:

   ```bash
   xattr -cr WhiteHatLabs.app
   ```

5. Start the app:

   ```bash
   open WhiteHatLabs.app
   ```

6. Open:

   ```text
   http://localhost:5051
   ```

## Windows Setup

1. Download `WhiteHatLabs-DAST-v1.2.exe`.
2. Double-click the EXE.
3. Open:

   ```text
   http://localhost:5051
   ```

## Burp Setup

The DAST app can import Burp proxy history through the included Burp extension.

The Mac ZIP includes:

```text
burp_extension.py
BURP_SETUP.md
```

### Burp Extension

1. Open Burp Suite.
2. Go to `Extensions`.
3. If Burp asks for Python/Jython support, configure Jython first:
   - Download Jython standalone JAR.
   - In Burp, open `Extensions -> Settings -> Python Environment`.
   - Select the Jython standalone JAR.
4. Click `Add`.
5. Extension type: `Python`.
6. Extension file: `burp_extension.py`.
7. Confirm the extension starts without errors.

### Required Ports

Burp should listen on:

```text
127.0.0.1:8080
```

The White Hat Labs Burp bridge/API should be reachable at:

```text
http://127.0.0.1:8090
```

The DAST app runs at:

```text
http://localhost:5051
```

## Docker Notes

No public Docker image is currently published because its Python files would be extractable. For an authorized private image build, run it with port mapping:

```bash
docker run -p 5051:5051 whitehatlabs-pentest
```

Then open:

```text
http://localhost:5051
```

If the Docker app needs to talk to Burp running on your laptop, do not use
`127.0.0.1` for Burp from inside the container. Inside Docker, `127.0.0.1`
means the container itself.

Use host gateway networking:

```bash
docker run -p 5051:5051 \
  --add-host=host.docker.internal:host-gateway \
  whitehatlabs-pentest
```

Then configure the app/Burp bridge to use:

```text
host.docker.internal:8080
host.docker.internal:8090
```

## Codex or Claude Agent Setup

The scanner agent can use local CLI tools when they are installed and
authenticated on the same machine.

### Codex CLI

Check whether Codex is installed:

```bash
codex --version
```

If it is missing, install Codex CLI from OpenAI's official instructions:

https://developers.openai.com/codex/cli

Common install commands:

macOS or Linux:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"
```

After install, sign in or authenticate Codex, then verify:

```bash
codex --version
```

### Claude Code

Check whether Claude Code is installed:

```bash
claude --version
```

If Claude is installed but not authenticated:

```bash
claude login
```

Restart White Hat Labs DAST after installing or authenticating CLI tools.

## Ask Codex To Install It

You can ask Codex:

```text
Install and start White Hat Labs DAST from this folder.
Follow INSTALLATION_DAST.md exactly.
Make sure the app opens at http://localhost:5051.
If Burp is installed, load burp_extension.py and confirm the Burp bridge is reachable.
Do not upload source code anywhere.
```

## Success Check

The setup is working when:

- `http://localhost:5051` opens.
- Burp tab shows connected after loading `burp_extension.py`.
- Burp proxy history can be imported.
- A new engagement starts cleanly.
- Scanner logs do not show missing CLI errors.

## Troubleshooting

### Port 5051 already in use

Find the process:

```bash
lsof -nP -iTCP:5051 -sTCP:LISTEN
```

Stop the old app process, then start White Hat Labs DAST again.

### Burp not connected

Check:

- Burp is open.
- Burp proxy is listening on `127.0.0.1:8080`.
- `burp_extension.py` is loaded.
- The Burp bridge/API is reachable at `127.0.0.1:8090`.

### Docker cannot reach Burp

Use:

```text
host.docker.internal
```

instead of:

```text
127.0.0.1
```

from inside Docker.
