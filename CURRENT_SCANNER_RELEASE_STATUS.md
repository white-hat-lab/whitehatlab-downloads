# Current scanner release status

Updated September 5, 2026.

The DAST v1.2, SAST/SCA v1.0, and network v1.0 downloads are legacy packages. They remain available for historical access, but they are not presented as builds of the current fixed scanner code.

The current scanner source is maintained privately. Its Docker delivery definitions and Compose configuration have been updated with separate DAST, SAST/SCA, and network build contexts. Those definitions exclude local credentials, reports, scan databases, cached targets, machine-specific MCP configuration, build output, and packaged applications.

No replacement native scanner binary is published in this repository yet:

- the current DAST and network source trees do not have complete, current native packaging specifications;
- the existing SAST packaging specifications refer to private/machine-local files that are not part of the clean source tree;
- a binary built from those incomplete inputs would not be a validated release.

SAST/SCA is published as a Docker image (`ghcr.io/white-hat-lab/whitehat-all-sast-sca`). The image ships compiled bytecode (`.pyc`) only; `.py` sources are removed at build time. Bytecode can still be decompiled with effort, the same as the packaged native binaries, so this is a practical barrier, not a cryptographic one. The image is validated by the release workflow's clean-container health check before publication. DAST and network images remain unpublished.

The next scanner binary release should be published only after its packaging inputs are made reproducible and the resulting artifact passes clean-machine startup and no-target smoke tests. No active scan against an external system is required for that release validation.

Native SAST packages (v1.1, Mac and Windows) are built by CI from the same private source with PyInstaller and contain compiled bytecode only, like the Docker image.
