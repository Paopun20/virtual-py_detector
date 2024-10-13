import os
import re
import subprocess
import ctypes
import platform
import sys
import time
import psutil  # Install with `pip install psutil`
from concurrent.futures import ThreadPoolExecutor, as_completed

class virtualpydetector:
    """A class to detect virtual environments, sandboxes, and debuggers."""

    class VMChecks:
        """Inner class containing VM-specific detection methods."""

        @staticmethod
        def check_vm_hardware():
            """Check for VM-specific hardware models."""
            system = platform.system()
            if system == "Windows":
                try:
                    output = subprocess.check_output(
                        ["wmic", "computersystem", "get", "model"],
                        encoding='utf-8', timeout=3
                    )
                    return any(vm in output for vm in ["Virtual", "VMware", "VirtualBox", "Hyper-V", "QEMU"])
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    return False
            elif system == "Darwin":  # macOS
                try:
                    output = subprocess.check_output(["sysctl", "hw.model"], encoding="utf-8", timeout=3)
                    return "VMware" in output or "VirtualBox" in output
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    return False
            return False

        @staticmethod
        def check_mac_address():
            """Check for known VM MAC address prefixes."""
            try:
                output = subprocess.check_output(
                    ["ifconfig" if platform.system() != "Windows" else "getmac"], 
                    encoding='utf-8', timeout=3
                )
                return re.search(r"(00:05:69|00:0C:29|00:50:56|00:1C:14|00:03:FF|00:05:00)", output) is not None
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return False

        @staticmethod
        def check_vm_artifacts():
            """Check for virtualization software artifacts."""
            vm_paths = [
                "/Applications/VMware Tools",  # macOS
                "/Applications/VirtualBox.app",
                "C:\\Program Files\\VMware\\VMware Tools",  # Windows
                "C:\\Program Files\\Oracle\\VirtualBox Guest Additions"
            ]
            return virtualpydetector.HelperFunctions.check_paths_exist(vm_paths)

        @staticmethod
        def check_virtualbox_drivers():
            """Check for VirtualBox drivers (only on Windows)."""
            if platform.system() != "Windows":
                return False
            drivers = ["VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys"]
            driver_paths = [f"C:\\Windows\\System32\\drivers\\{driver}" for driver in drivers]
            return virtualpydetector.HelperFunctions.check_paths_exist(driver_paths)

        @staticmethod
        def check_cpu_features():
            """Check for CPU features indicating virtualization."""
            if platform.system() == "Linux":
                try:
                    with open("/proc/cpuinfo", "r") as cpuinfo:
                        return any("hypervisor" in line for line in cpuinfo)
                except FileNotFoundError:
                    return False
            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(["sysctl", "machdep.cpu.features"], encoding="utf-8", timeout=3)
                    return "VMM" in output  # VMM indicates macOS virtualization
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    return False
            return False

    class DebuggerChecks:
        """Inner class containing debugger and sandbox detection methods."""

        @staticmethod
        def check_hypervisor():
            """Check if running in a hypervisor using platform-specific APIs."""
            if platform.system() == "Windows":
                try:
                    return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(29))
                except (AttributeError, OSError):
                    return False
            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(["sysctl", "kern.hv_support"], encoding="utf-8", timeout=3)
                    return "1" in output  # Hypervisor is enabled
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    return False
            return False

        @staticmethod
        def check_sandbox_files():
            """Check for specific sandbox files or paths."""
            sandbox_files = [
                "/Applications/WindowsSandbox.app",  # Hypothetical path on macOS
                "C:\\Program Files\\WindowsApps\\Microsoft.WindowsSandbox_"
            ]
            return virtualpydetector.HelperFunctions.check_paths_exist(sandbox_files)

        @staticmethod
        def detect_debugger():
            """Detect if a debugger is attached using platform-specific methods."""
            if platform.system() == "Windows":
                try:
                    return bool(ctypes.windll.kernel32.IsDebuggerPresent())
                except (AttributeError, OSError):
                    return False
            elif platform.system() in {"Darwin", "Linux"}:
                try:
                    parent = psutil.Process(os.getppid()).name().lower()
                    return parent in {"lldb", "gdb"}
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False
            return False

        @staticmethod
        def anti_timing_check():
            """Detect timing discrepancies caused by virtualization or debugging."""
            start_time = time.perf_counter()
            for _ in range(1_000_000):
                pass  # Run a loop to measure timing
            elapsed = time.perf_counter() - start_time
            return elapsed > 0.5  # Adjust threshold as needed

    class ProcessChecks:
        """Inner class to detect suspicious processes."""

        @staticmethod
        def detect_suspicious_processes():
            """Detect known sandbox or VM processes using threading for speed."""
            suspicious_processes = {
                "vmtoolsd", "vboxservice", "wireshark", 
                "fiddler", "sandboxie", "processhacker"
            }

            def is_suspicious(proc):
                try:
                    return proc.info['name'].lower() in suspicious_processes
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False

            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(is_suspicious, proc) for proc in psutil.process_iter(['name'])]
                return any(f.result() for f in as_completed(futures))

    class HelperFunctions:
        """Inner class with utility methods."""

        @staticmethod
        def check_paths_exist(paths):
            """Check if any given paths exist."""
            return any(os.path.exists(path) for path in paths)

    def detect(self) -> bool:
        """Combine all checks for VM, sandbox, and debugging detection."""
        checks = [
            self.VMChecks.check_vm_hardware(),
            self.VMChecks.check_mac_address(),
            self.VMChecks.check_vm_artifacts(),
            self.VMChecks.check_virtualbox_drivers(),
            self.VMChecks.check_cpu_features(),
            self.DebuggerChecks.check_hypervisor(),
            self.DebuggerChecks.check_sandbox_files(),
            self.DebuggerChecks.detect_debugger(),
            self.DebuggerChecks.anti_timing_check(),
            self.ProcessChecks.detect_suspicious_processes()
        ]
        return any(checks)
