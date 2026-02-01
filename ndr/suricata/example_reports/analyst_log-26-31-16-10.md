# Analyst Log - Linux Host Identification
**Date:** 2026-01-31
**Analyst:** Gemini CLI

## Objective
Identify likely Linux systems within the network that are assigned RFC 1918 (private) IP addresses.

## Methodology
1.  **Tooling:** Developed `find_linux_hosts.py`.
2.  **Data Source:** Suricata EVE logs (`logs/*.json`).
3.  **Logic:**
    -   Filtered for source IPs belonging to RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    -   Scored hosts based on traffic matching known Linux indicators:
        -   **Domains:** `ubuntu.com`, `debian.org`, `snapcraft.io`, `pypi.org`, `pythonhosted.org`, etc.
        -   **User Agents:** `curl`, `wget`, `apt`, `linux` (in HTTP headers).
    -   Scoring:
        -   Strong indicators (Hostnames/SNI): +2 points
        -   Moderate indicators (DNS, User-Agents): +1 point

## Findings

The following hosts were identified as likely Linux systems, sorted by confidence score.

### High Confidence (Likely Ubuntu/Snapcraft Usage)
These hosts show frequent communication with Ubuntu update servers and the Snapcraft store.

*   **192.168.2.173** (Score: 320)
    *   *Indicators:* `api.snapcraft.io`, `motd.ubuntu.com`, `esm.ubuntu.com`, `images.lxd.canonical.com`.
    *   *Notes:* Likely an Ubuntu Server or Desktop using LXD containers.
*   **192.168.2.223** (Score: 202)
    *   *Indicators:* `files.pythonhosted.org`, `api.snapcraft.io`, `pypi.org`.
    *   *Notes:* Significant Python development/usage activity.
*   **192.168.2.180** (Score: 194)
    *   *Indicators:* `api.snapcraft.io`, `motd.ubuntu.com`.
*   **192.168.2.167** (Score: 158)
    *   *Indicators:* `api.snapcraft.io`, `motd.ubuntu.com`.

### Moderate Confidence
*   **192.168.2.197**, **192.168.2.101**, **192.168.2.128**:
    *   Regular communication with `motd.ubuntu.com` and `esm.ubuntu.com` suggests these are active Ubuntu systems checking for updates/messages.

### Other Linux Flavors
*   **192.168.2.219**, **192.168.2.194**:
    *   Communicated with `deb.debian.org`, indicating they are likely **Debian** systems.

### Python/Dev Focus
*   **192.168.3.124**:
    *   Traffic to `pypi.org` and `files.pythonhosted.org` without strong OS-specific update traffic detected in this window. Likely Linux or a dev workstation.

## Script Used
`find_linux_hosts.py`
