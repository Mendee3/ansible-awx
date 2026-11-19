# armada-hunt

Read-only AWX/Ansible hunt for the ARMADA implant set:

- `guard`: watchdog and persistence implant
- `kworkerd`: the bot, with miner, DDoS, SOCKS, Tor/I2P C2
- `libproc.so`: LD_PRELOAD rootkit

Targets RHEL, CentOS 7+, AlmaLinux, Rocky, Ubuntu and Debian on x86_64 and aarch64, including Docker, Podman and containerd overlay layers on those hosts.

## Layout

```
armada_hunt.yml          playbook (AWX job template)
files/armada_hunt.sh     hunt logic (POSIX sh, runs under static busybox)
files/busybox/           static busybox per arch: busybox-<ansible_architecture>
```

## Why static busybox

The rootkit registers `/usr/lib/libproc.so` in `/etc/ld.so.preload`. It hooks `readdir`, `open`, `stat`, `unlink` and other calls in every dynamically linked program, so `sh`, `ls`, `grep`, `find` and python cannot see hidden files, processes or ports.

A static binary never loads `ld.so.preload`. The hunt runs entirely under the pushed static busybox and then compares its own view with the system's `ls` and `cat`. Anything only the static view can see is reported as `rootkit-hidden-*`.

If busybox is missing, fails to run (for example because of `fapolicyd` or a `noexec` filesystem), or turns out to be dynamic, the hunt runs **degraded**. Every host is then reported at least as `REVIEW`. Set `armada_require_static: true` to fail those hosts instead.

## Bundled busybox

`files/busybox/SHA256SUMS` lists the expected hashes. Both binaries come from Kali `busybox-static 1:1.38.0-3+b2`, verified through the signed `InRelease` file, then `Packages.gz`, then the `.deb` SHA256.

| file | sha256 |
|---|---|
| busybox-x86_64 | 7608fb9732b11e9cd0f7cdeaa537ca61a4991907b83b2fdf6fcdcb577f07d932 |
| busybox-aarch64 | 56c16b82816bef1bf861e89d2208f859c3751a2adeb4c72233bf4d44879e7d6e |

Instead of bundling, you can set `armada_busybox_urls` / `armada_busybox_sha256` per architecture to an internal mirror.

## Variables (survey-friendly)

| var | default | |
|---|---|---|
| `armada_fail_on_hit` | true | mark INFECTED hosts failed |
| `armada_require_static` | false | fail host if static busybox can't be used |
| `armada_scan_home` | true | recurse /root, /home |
| `armada_scan_containers` | true | scan container overlay layers |
| `armada_work_base` | /root | where busybox is staged (must allow exec) |
| `armada_extra_hashes` | [] | more SHA256 IOCs |
| `armada_timeout` | 1800 | seconds |

## Results

- Per host: `INFECTED` (any HIT), `REVIEW` (SUSPECT only, or degraded mode), or `CLEAN`.
- Job artifacts: `armada_hunt` (per host: status, mode, os, hits, suspects, info) and `armada_infected_hosts`, for downstream workflow nodes.

To map an overlay-layer hit to its container:

```
docker inspect --format '{{.Name}} {{.GraphDriver.Data.UpperDir}}' $(docker ps -aq)
```

## Requirements

- Privilege escalation (root).
- Only `ansible.builtin` modules are used.
- CentOS 7 (python 2.7) and RHEL 8 (platform-python 3.6) targets need an execution environment with **ansible-core <= 2.16**.
- Tested with ansible-core 2.16.20.
