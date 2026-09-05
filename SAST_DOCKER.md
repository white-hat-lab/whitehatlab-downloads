# SAST + SCA Scanner — Docker guide

Run the WhiteHatLabs static analysis scanner on your own machine. Your source code never leaves it, except the parts the AI review sends to Anthropic's Claude API (see [What leaves your machine](#what-leaves-your-machine)).

Image: `ghcr.io/white-hat-lab/whitehat-all-sast-sca` · Platform: linux/amd64 (Apple Silicon runs it under emulation; expect roughly 2× longer scans) · Size: about 4 GB, because every analysis tool is bundled.

## 1. What you need

| Requirement | Why |
|---|---|
| Docker Desktop (macOS/Windows) or Docker Engine 24+ (Linux) | runs the image |
| A Claude subscription (Pro/Max/Team) **or** an Anthropic API key | the AI review runs through Claude Code |
| Internet access from the container | GitHub clones, OSV advisory lookups, Semgrep rules |
| 8 GB RAM, 10 GB free disk | CodeQL databases and the image |

## 2. Install and start

```bash
mkdir whitehat-sast && cd whitehat-sast
curl -fsSLO https://raw.githubusercontent.com/white-hat-lab/whitehatlab-downloads/main/docker-compose.yml
docker compose up -d
```

Open **http://localhost:5056**. The UI is bound to localhost only.

Everything the scanner writes (scans, reports, caches, your Claude sign-in) lives in the Docker volume `whitehat-data`, so upgrades keep your history.

## 3. Sign in the AI agent (once)

Pick one:

**Claude subscription (recommended)**

```bash
docker exec -it whitehat-sast claude auth login
```

Follow the printed link, sign in, paste the code back. The sign-in is stored in the data volume, so you do this once.

**Anthropic API key**

Edit `docker-compose.yml`, uncomment `ANTHROPIC_API_KEY`, set your key, and run `docker compose up -d` again. Usage is billed to that key.

## 4. Run a scan, end to end

1. **Paste a GitHub URL** (public, or private if the container can reach it) or **Upload a ZIP** of the source.
2. Choose options: **Skip SCA** to skip dependency scanning, **Fresh scan** to ignore any previous baseline for this project.
3. Click **Check setup**. The scanner inspects the project's languages and verifies, for that project only:
   - the AI agent is signed in and answers a test prompt;
   - every analysis tool the project needs is present and runs (they are all bundled, so this passes unless the project needs something unusual);
   - language-specific inputs, for example a Go module or compiled classes if you configured SpotBugs.
   Each failed check shows the reason, exact fix steps, and a **Repair automatically** button where a safe install exists.
4. Click **Start scan** once every check is green. The checks are repeated at start; a scan never runs on a broken setup.
5. Watch the **Scanner** tab. It shows what is running, what was skipped and why, files sent for AI review, and how many dangerous call sites the AI judged.
6. Open the **Report** tab when it finishes. Findings are grouped by severity, type, or file, each with the code, the data flow, a fix, and where the same issue was also reported. "Not verified by AI" and "By design / hygiene" sections are listed separately and not counted.
7. Export with the buttons at the top of the report: HTML, CSV, Word, remediated code. The SCA report (dependencies, advisories, reachability) has its own button when SCA ran.

A scan of a 5,000-line project takes about 5–10 minutes; almost all of it is the AI review.

## 5. What the scanner does

| Stage | Engine | Languages |
|---|---|---|
| Pattern rules and taint tracking | built in | Python, Java/Kotlin, Go, JavaScript/TypeScript, Ruby, Rust, Solidity, Swift, C# |
| Semantic data-flow analysis | CodeQL | Go, Python, JavaScript/TypeScript, Java/Kotlin, C/C++, C#, Ruby, Swift |
| Community security rules | Semgrep | all of the above |
| Language specialists | bandit, dlint, gosec, flawfinder, slither, brakeman, clippy | as applicable |
| Secrets, infrastructure-as-code, API security | built in | all |
| Dependency scanning (SCA) | OSV advisories + reachability | Python, Node, Go, Rust, Ruby, Java, .NET manifests |
| AI review | Claude Code | every dangerous call site gets a verdict; new issues are discovered; candidates are verified |

AI and agent applications (MCP servers, LangChain tools, LLM prompts) get dedicated checks: prompt injection, poisoned tool descriptions, excessive tool capability, secrets returned to the model.

PHP is not supported: a submission containing PHP is refused at the setup check.

## 6. What leaves your machine

- Source code stays in the container's volume.
- The AI review sends code excerpts to Anthropic's Claude API under your subscription or key. No other service receives your code.
- Dependency scanning queries the public OSV database with package names and versions.
- Semgrep downloads its public rule packs; metrics are off.

If any of that is unacceptable for a codebase, run the scan with the AI agent signed out: the setup check will block, by design. There is no offline mode.

## 7. Upgrade, data, uninstall

```bash
docker compose pull && docker compose up -d      # upgrade
docker run --rm -v whitehat-data:/data alpine ls /data/scans   # look at stored scans
docker compose down                               # stop (keeps data)
docker compose down -v                            # stop and delete all scan data
```

## 8. Troubleshooting

| Symptom | What to do |
|---|---|
| Setup check says the AI agent is not signed in | `docker exec -it whitehat-sast claude auth login`, then **Recheck** |
| A tool check fails inside the container | Click **Repair automatically**; it runs the shown command inside the container. If it fails, the panel shows the manual steps. |
| Scan stays in the AI stage for a long time | Normal for large projects; the AI reviews in parallel groups. Keep the computer awake. |
| A scan shows "Interrupted" | The container was stopped or the machine slept mid-scan. Start it again. |
| Port 5056 already in use | Change the left side of `"127.0.0.1:5056:5056"` in `docker-compose.yml`. |
| Apple Silicon: slow | The image is amd64; Docker Desktop runs it through Rosetta. Enable "Use Rosetta for x86_64/amd64 emulation" in Docker Desktop settings. |

## 9. Reading the numbers honestly

The finding count is not a vulnerability count for the whole application. It is the set of issues the listed stages could see, each reported once. The report's **Scan coverage** section says which stages ran, how many files reached the AI, and how many dangerous call sites got a verdict. A clean scan means those stages found nothing, not that nothing exists.
