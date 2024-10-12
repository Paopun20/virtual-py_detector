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
   git clone https://github.com/yourusername/VirtualPy-Detector.git
   cd VirtualPy-Detector
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

## Disclaimer
This tool is intended for **educational and research purposes only**. Use it responsibly and in accordance with applicable laws and regulations.

## License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.
