# Current scanner release status

Updated September 4, 2026.

The native DAST v1.2, SAST/SCA v1.0, and network v1.0 releases do not represent the current scanner source. The main SAST/SCA download instructions now use Docker.

The SAST/SCA container build, startup health check, and publication job succeeded in the August 10 release workflow. Its Linux AMD64 image is available at `ghcr.io/white-hat-lab/whitehat-all-sast-sca:latest` to authorized accounts. Registry manifest access was verified on September 4. Full local scan validation is pending; Docker was not running on the validation machine. An overall workflow failure must not be interpreted as failure of every component job.

The current scanner source is maintained privately. Its Docker delivery definitions and Compose configuration have been updated with separate DAST, SAST/SCA, and network build contexts. Those definitions exclude local credentials, reports, scan databases, cached targets, machine-specific MCP configuration, build output, and packaged applications.

No replacement native scanner binary is published in this repository yet:

- the current DAST and network source trees do not have complete, current native packaging specifications;
- the existing SAST packaging specifications refer to private/machine-local files that are not part of the clean source tree;
- a binary built from those incomplete inputs would not be a validated release.

No public Docker registry image is published. Python application files in a container image are readily extractable, which would conflict with the private-source distribution policy.

The next scanner binary release should be published only after its packaging inputs are made reproducible and the resulting artifact passes clean-machine startup and no-target smoke tests. No active scan against an external system is required for that release validation.
