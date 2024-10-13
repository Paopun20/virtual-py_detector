# Virtual-Py Detector
A Python-based detection tool designed to identify virtual machines, sandboxes, and debuggers. VirtualPy Detector leverages multiple techniques, such as hardware checks, driver detection, anti-debugging mechanisms, and sandbox artifact searches, to prevent execution in restricted or emulated environments.

## Features
- **Virtual Machine Detection**  
  Detects VMware, VirtualBox, Hyper-V, and QEMU environments.
- **Sandbox Detection**  
  Identifies sandbox-specific files and Windows Sandbox installations.
- **Anti-Debugging**  
  Detects debuggers using Windows API calls and timing-based techniques.
- **Suspicious Process Detection**  
  Monitors for processes like Wireshark, ProcessHacker, and Sandboxie.
- **Cross-Platform Compatibility**  
  Works on **Windows** and **Linux** with platform-specific checks.

## Requirements
- **Python 3.6+**
- Install the following dependencies:
  ```bash
  pip install psutil
  ```

## Installation
1. **Clone the repository:**  
   ```bash
   git clone https://github.com/Paopun20/virtual-py_detector.git
   cd virtual-py_detector
   ```

2. **Install dependencies:**  
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the VirtualPy Detector to check if the current environment is a virtual machine, sandbox, or debugger:
```bash
python virtualpy_detector.py
```

### Example Output:
```
virtualpy-detector: Detected
```
or  
```
virtualpy-detector: Not Detected
```

## Project Structure
```
VirtualPy-Detector/
│
├── virtualpy_detector.py   # Main detection script
├── requirements.txt        # Python dependencies
├── README.md               # Documentation
└── LICENSE                 # License file (optional)
└── example.py              # Main example script
```

## How It Works
VirtualPy Detector runs multiple checks to identify restricted environments:

1. **Hardware Checks:**  
   Queries system hardware models for virtualization indicators.
2. **Driver Detection:**  
   Looks for VirtualBox, VMware, or other virtualization drivers.
3. **MAC Address Validation:**  
   Identifies known VM-specific MAC address prefixes.
4. **Anti-Debugging Mechanisms:**  
   Uses Windows API to detect debuggers and measures loop timing to identify delays.
5. **Process Scanning:**  
   Detects suspicious processes commonly used in sandboxes or forensic tools.

## Supported Platforms
- **Windows 10+**
- **Linux**
- **macOS**

# Test Status Checklist
   ## Virtual Machines (VM)
   - **Windows**
     - [ ] Windows 10: Test
     - [ ] Windows 11: Untest
   - **Linux**
     - [ ] Linux: Untest
   - **MacOS**
     - [ ] MacOS: Untest
   
   ## VirtualBox
   - **Windows**
     - [ ] Windows 10: Untest
     - [ ] Windows 11: Untest
   - **Linux**
     - [ ] Linux: Untest
   - **MacOS**
     - [ ] MacOS: Untest
   
   ## Real Machines
   - **Windows**
     - [ ] Windows 10: Test
     - [ ] Windows 11: Untest
   - **Linux**
     - [ ] Linux: Untest
   - **MacOS**
     - [ ] MacOS: Untest
