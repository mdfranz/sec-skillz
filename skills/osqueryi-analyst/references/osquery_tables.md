# osquery Table Reference

## Key Tables for Security Investigation

### Process Visibility
| Table | Description | Platform |
|-------|-------------|----------|
| `processes` | All running processes with pid, ppid, path, cmdline, uid, start_time | L/M/W |
| `process_open_sockets` | Open network sockets per process | L/M/W |
| `process_open_files` | File descriptors held by processes | L/M |
| `process_memory_map` | Memory-mapped regions per process (requires root) | L/M |
| `process_envs` | Environment variables per process | L/M/W |

### Network
| Table | Description | Platform |
|-------|-------------|----------|
| `listening_ports` | Ports bound and listening | L/M/W |
| `process_open_sockets` | Active TCP/UDP connections | L/M/W |
| `arp_cache` | ARP table entries | L/M/W |
| `dns_resolvers` | Configured DNS servers | L/M/W |
| `etc_hosts` | /etc/hosts entries | L/M/W |
| `interface_addresses` | IP addresses per interface | L/M/W |

### Persistence
| Table | Description | Platform |
|-------|-------------|----------|
| `crontab` | Cron job entries | L/M |
| `startup_items` | Login/startup items | M |
| `launchd` | LaunchDaemons and LaunchAgents | M |
| `systemd_units` | systemd unit files and their state | L |
| `scheduled_tasks` | Windows Task Scheduler entries | W |
| `registry` | Windows registry key/values | W |
| `services` | Windows services | W |
| `rc_scripts` | SysV init scripts | L |

### Users and Authentication
| Table | Description | Platform |
|-------|-------------|----------|
| `users` | Local user accounts | L/M/W |
| `groups` | Local groups | L/M/W |
| `logged_in_users` | Active login sessions | L/M/W |
| `last` | Historical login records (wtmp) | L/M |
| `sudoers` | /etc/sudoers entries | L/M |
| `user_ssh_keys` | SSH public/private keys per user | L/M |
| `authorized_keys` | SSH authorized_keys entries | L/M |
| `shadow` | Password shadow file (requires root) | L |

### File System
| Table | Description | Platform |
|-------|-------------|----------|
| `file` | File metadata by path or glob | L/M/W |
| `hash` | MD5/SHA1/SHA256 of files | L/M/W |
| `magic` | File magic/MIME type | L/M |
| `yara` | YARA scan results (requires rules) | L/M/W |
| `suid_bin` | SUID/SGID binaries | L/M |
| `sip_config` | macOS SIP status | M |

### System Info
| Table | Description | Platform |
|-------|-------------|----------|
| `system_info` | Hostname, CPU, memory, UUID | L/M/W |
| `os_version` | OS name and version | L/M/W |
| `uptime` | System uptime | L/M/W |
| `kernel_info` | Kernel version and boot args | L/M/W |
| `kernel_modules` | Loaded kernel modules | L |
| `kextstat` | Loaded kernel extensions | M |
| `patches` | Installed patches/hotfixes | W |

### macOS Specific
| Table | Description |
|-------|-------------|
| `launchd` | LaunchDaemons/Agents with their path and program args |
| `crashes` | Application crash reports |
| `certificates` | Keychain certificates |
| `safari_extensions` | Installed Safari extensions |
| `unified_log` | macOS Unified Log (requires osquery extension) |

### Linux Specific
| Table | Description |
|-------|-------------|
| `systemd_units` | All systemd units and active state |
| `iptables` | iptables firewall rules |
| `apparmor_profiles` | AppArmor profile status |
| `selinux_settings` | SELinux configuration |
| `socket_events` | Audit-based socket events (requires auditd) |
| `process_events` | Audit-based exec events (requires auditd) |

### Windows Specific
| Table | Description |
|-------|-------------|
| `registry` | Registry keys and values |
| `windows_events` | Windows Event Log entries |
| `certificates` | Certificate store |
| `drivers` | Loaded drivers |
| `wmi_cli_event_consumers` | WMI persistence |
| `wmi_event_filters` | WMI event filter persistence |

**Platform key**: L = Linux, M = macOS, W = Windows

## Useful Meta-Commands (osqueryi shell)
```
.tables              -- list all available tables
.schema <table>      -- show column definitions for a table
.mode json|csv|line|pretty
.output <file>       -- redirect output to file
.output stdout       -- reset output to terminal
.quit                -- exit osqueryi
```
