import os
import re
import subprocess
import ctypes
import platform
import sys
import time
import psutil  # Install with `pip install psutil`

class virtualpydetector:
    """A class for anti-sandbox, anti-VM, and anti-debugging detection."""

    class Function:
        @staticmethod
        def check_vm_hardware():
            """Check for VM-specific hardware models."""
            try:
                output = subprocess.check_output(
                    ["wmic", "computersystem", "get", "model"], 
                    encoding='utf-8', timeout=3
                )
                return any(vm in output for vm in ["Virtual", "VMware", "VirtualBox", "Hyper-V", "QEMU"])
            except subprocess.CalledProcessError:
                return False

        @staticmethod
        def check_mac_address():
            """Check for known VM MAC address prefixes."""
            try:
                output = subprocess.check_output(["getmac"], encoding='utf-8', timeout=3)
                return re.search(r"(00:05:69|00:0C:29|00:50:56|00:1C:14|00:03:FF|00:05:00)", output) is not None
            except subprocess.CalledProcessError:
                return False

        @staticmethod
        def check_paths_exist(paths):
            """Helper function to check if any given paths exist."""
            return any(os.path.exists(path) for path in paths)

        @staticmethod
        def check_vm_artifacts():
            """Check for virtualization software artifacts."""
            vm_paths = [
                os.path.join("C:\\Program Files", "VMware", "VMware Tools"),
                os.path.join("C:\\Program Files", "Oracle", "VirtualBox Guest Additions"),
                os.path.join("C:\\Program Files", "Microsoft Virtual PC"),
                os.path.join("C:\\Program Files", "Hyper-V")
            ]
            return virtualpydetector.Function.check_paths_exist(vm_paths)

        @staticmethod
        def check_virtualbox_drivers():
            """Check for VirtualBox specific drivers."""
            drivers = ["VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys"]
            driver_paths = [os.path.join("C:\\Windows\\System32\\drivers", driver) for driver in drivers]
            return virtualpydetector.Function.check_paths_exist(driver_paths)

        @staticmethod
        def check_cpu_features():
            """Check for CPU features indicating virtualization."""
            if platform.system() != "Linux":
                return False
            try:
                with open("/proc/cpuinfo", "r") as cpuinfo:
                    return any("hypervisor" in line for line in cpuinfo)
            except FileNotFoundError:
                return False

        @staticmethod
        def check_hypervisor():
            """Check if running in a hypervisor using Windows APIs."""
            try:
                return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(29))
            except AttributeError:
                return False

        @staticmethod
        def check_windows_sandbox():
            """Check for Windows Sandbox environment."""
            try:
                output = subprocess.check_output(
                    ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Windows Sandbox'],
                    stderr=subprocess.DEVNULL, encoding='utf-8', timeout=3
                )
                return "Microsoft Windows Sandbox" in output
            except subprocess.CalledProcessError:
                return False

        @staticmethod
        def check_sandbox_files():
            """Check for specific files indicating sandbox environments."""
            sandbox_files = [
                "C:\\Program Files\\WindowsApps\\Microsoft.WindowsSandbox_",
                "C:\\Program Files\\WindowsApps\\Microsoft.Sandbox_"
            ]
            return virtualpydetector.Function.check_paths_exist(sandbox_files)

        @staticmethod
        def detect_debugger():
            """Detect if a debugger is attached using Windows API."""
            try:
                is_debugged = ctypes.windll.kernel32.IsDebuggerPresent()
                return bool(is_debugged)
            except AttributeError:
                return False

        @staticmethod
        def anti_timing_check():
            """Detect timing discrepancies caused by virtualization or debugging."""
            start_time = time.time()
            for _ in range(1000000):
                pass  # Run a loop to measure timing
            end_time = time.time()
            elapsed = end_time - start_time
            # If the loop takes too long, it might be running in a VM or debugger.
            return elapsed > 0.5  # Adjust threshold as needed

        @staticmethod
        def detect_suspicious_processes():
            """Detect known sandbox or VM processes."""
            suspicious_processes = [
                "vmtoolsd.exe", "vboxservice.exe", "wireshark.exe", 
                "fiddler.exe", "sandboxie.exe", "processhacker.exe"
            ]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in suspicious_processes:
                    return True
            return False

    def virtualpy_detector(self) -> bool:
        """Combine all checks for VM, sandbox, and debugging detection."""
        checks = [
            self.Function.check_vm_hardware(),
            self.Function.check_mac_address(),
            self.Function.check_vm_artifacts(),
            self.Function.check_virtualbox_drivers(),
            self.Function.check_cpu_features(),
            self.Function.check_hypervisor(),
            self.Function.check_windows_sandbox(),
            self.Function.check_sandbox_files(),
            self.Function.detect_debugger(),
            self.Function.anti_timing_check(),
            self.Function.detect_suspicious_processes()
        ]
        return any(checks)

if __name__ == "__main__":
    detector = virtualpydetector()
    if detector.virtualpy_detector():
        print("virtualpy-detector: Detected")
    else:
        print("virtualpy-detector: Not Detected")
