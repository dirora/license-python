"""Machine identity: fingerprint, hashed hardware components, VM detection."""
from __future__ import annotations

import hashlib
import os
import platform as _platform
import re
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

_GUID = re.compile(r"MachineGuid\s+REG_SZ\s+(\S+)")
_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')
_REG = re.compile(r"REG_SZ\s+(.+)")

VM_MARKERS = ("vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "virtual machine",
              "parallels", "bochs", "bhyve", "google compute engine", "amazon ec2", "openstack")


def _run(*cmd: str) -> str:
    try:
        return subprocess.run(list(cmd), capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def machine_id() -> str:
    system = _platform.system()
    if system == "Windows":
        m = _GUID.search(_run("reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"))
        if m:
            return m.group(1)
    elif system == "Darwin":
        m = _UUID.search(_run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
        if m:
            return m.group(1)
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                v = Path(p).read_text().strip()
                if v:
                    return v
            except OSError:
                pass
    raise RuntimeError("machine id not found")


def hash_component(salt: str, name: str, value: str) -> str:
    """Salted SHA-256 of one hardware value (the raw value never leaves the machine)."""
    v = value.strip().lower()
    data = f"{salt}:{name}:{v}" if name else f"{salt}:{v}"
    return hashlib.sha256(data.encode()).hexdigest()


def machine_fingerprint(salt: str) -> str:
    """SHA-256 of the OS machine id salted with ``salt``: 64 hex characters."""
    return hash_component(salt, "", machine_id())


def looks_virtual(s: str) -> bool:
    s = s.lower()
    return any(m in s for m in VM_MARKERS)


def is_virtual() -> bool:
    system = _platform.system()
    if system == "Linux":
        for f in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor"):
            try:
                if looks_virtual(Path(f).read_text()):
                    return True
            except OSError:
                pass
        if Path("/.dockerenv").exists():
            return True
        try:
            cg = Path("/proc/1/cgroup").read_text()
            if any(w in cg for w in ("docker", "kubepods", "containerd", "lxc")):
                return True
        except OSError:
            pass
    elif system == "Darwin":
        return _run("sysctl", "-n", "kern.hv_vmm_present").strip() == "1"
    elif system == "Windows":
        for v in ("SystemProductName", "SystemManufacturer"):
            if looks_virtual(_run("reg", "query", r"HKLM\HARDWARE\DESCRIPTION\System\BIOS", "/v", v)):
                return True
    return False


def _cpu_model() -> str:
    system = _platform.system()
    if system == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith(("model name", "Hardware")) and ":" in line:
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    elif system == "Darwin":
        return _run("sysctl", "-n", "machdep.cpu.brand_string").strip()
    elif system == "Windows":
        m = _REG.search(_run("reg", "query", r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "/v", "ProcessorNameString"))
        if m:
            return m.group(1).strip()
    return _platform.processor()


def _mac() -> str:
    node = uuid.getnode()
    if (node >> 40) & 1:  # random (multicast bit set): no real hardware address
        return ""
    return ":".join(f"{(node >> s) & 0xff:02x}" for s in range(40, -1, -8))


@dataclass
class HardwareInfo:
    components: Dict[str, str] = field(default_factory=dict)
    virtual: bool = False


def collect_hardware(salt: str) -> HardwareInfo:
    """Hashed components (machine_id, hostname, mac, cpu, os) and the VM flag."""
    comps: Dict[str, str] = {}

    def add(name: str, value: Optional[str]) -> None:
        if value and value.strip():
            comps[name] = hash_component(salt, name, value)

    try:
        add("machine_id", machine_id())
    except RuntimeError:
        pass
    add("hostname", socket.gethostname())
    add("mac", _mac())
    add("cpu", f"{_cpu_model()}|{os.cpu_count()}")
    add("os", f"{_platform.system().lower()}|{_platform.machine().lower()}")
    return HardwareInfo(comps, is_virtual())
