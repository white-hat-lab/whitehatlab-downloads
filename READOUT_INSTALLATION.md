# The Read-Out v1.0 Installation

The Read-Out is a standalone report generator. It does not require the Pentest app, Burp, Codex, Claude, or a scanner to be running.

## macOS / Linux

```bash
unzip TheReadOut.zip
cd Report_App
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open:

```text
http://localhost:5055
```

## Windows PowerShell

```powershell
Expand-Archive TheReadOut.zip
cd TheReadOut\Report_App
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open:

```text
http://localhost:5055
```

## Docker

```bash
docker build -t whitehatlabs-readout .
docker run --rm -p 5055:5055 whitehatlabs-readout
```

Open:

```text
http://localhost:5055
```

## Port

The default port is `5055`. To change it:

```bash
READOUT_PORT=5060 python3 app.py
```
