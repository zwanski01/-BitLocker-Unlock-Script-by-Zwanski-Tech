# BitLocker Pro

A command-line toolkit to assist in BitLocker password recovery by orchestrating `hashcat`. This tool is intended for security professionals, forensic investigators, and users who need to recover access to their own encrypted drives.

## ⚠️ Legal Disclaimer

**Important**: This tool is intended for:

*   Legitimate forensic investigations
*   Authorized penetration testing
*   Recovery of your own encrypted devices
*   Educational purposes

Never use this tool on systems you do not own or without explicit, written permission. Unauthorized use of this tool is illegal.

---

## 📋 Current Features (Implemented)

*   **Orchestrates Hashcat Attacks**: Wraps `hashcat` to provide a streamlined user experience for the following attack modes:
    *   **Dictionary Attack**: Uses one or more wordlists.
    *   **Bruteforce Attack**: Tries all character combinations within a given length and charset.
    *   **Mask Attack**: Pattern-based cracking for when parts of the password are known.
    *   **Hybrid Attack**: Combines wordlists with masks.
*   **GPU Acceleration**: Leverages `hashcat`'s ability to use GPUs for significantly faster cracking.
*   **Result Reporting**: Saves successfully recovered passwords to a JSON file.
*   **Cross-Platform**: Written in Go, can be compiled for Windows, macOS, and Linux (though dependencies are platform-specific).

## 🔧 Planned & Conceptual Features

This project has a roadmap to include more advanced forensic capabilities. The functions for these are stubbed in the code to show where they would be integrated.

*   **Real Hash Extraction**: Currently, the tool creates a dummy hash. A real implementation requires a dedicated forensic tool like `bitlocker2john.py`. The tool attempts to use `manage-bde` on Windows to provide some information, but this is not a full hash extraction.
*   **Memory Analysis**: Integration with tools like **Volatility** to find encryption keys in memory dumps.
*   **TPM Key Extraction**: Conceptual feature for extracting keys from a Trusted Platform Module. This is highly specialized.
*   **Cloud Recovery Key Checking**: Integration with Microsoft Account / Azure AD APIs to check for backed-up recovery keys.

---

## ⚙️ Installation & Setup

### 1. Prerequisites

You must install the necessary tools for your operating system.

**a) Go Language**

You need Go (version 1.18 or newer) to build the tool. Download it from [go.dev](https://go.dev/dl/).

**b) Hashcat**

This tool depends on `hashcat`. Download it from [hashcat.net/hashcat/](https://hashcat.net/hashcat/). Ensure the `hashcat` binary is in your system's PATH or provide the path via the `-hashcat` flag.

**c) (Optional) Wordlists**

For dictionary attacks, you need wordlists.
```bash
# Example on Debian/Ubuntu
sudo apt install wordlists
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

### 2. Go Dependencies

Open your terminal and run:
```bash
go get github.com/fatih/color
go get github.com/shirou/gopsutil/v3/disk
```

### 3. Build the Tool

Navigate to the project directory and run:
```bash
go build -o bitlocker-tool bitlocker-tool.go
```
On Windows, you can run `go build -o bitlocker-tool.exe bitlocker-tool.go`.

---

## 🚀 Usage Examples

**Important:** Hash extraction is not performed by this tool. You must first extract the BitLocker hash using a tool like **`bitlocker2john.py`** and save it to a file (e.g., `my_hash.txt`).

**Dictionary Attack:**
```bash
./bitlocker-tool -hash-file my_hash.txt -mode dictionary -wordlist /path/to/rockyou.txt
```

**Bruteforce Attack:**
```bash
./bitlocker-tool -hash-file my_hash.txt -mode bruteforce -min-length 4 -max-length 8 -charset "?l?u?d"
```

**Mask Attack:**
```bash
# Example: An 8-character password starting with 'pass' and ending with 4 digits
./bitlocker-tool -hash-file my_hash.txt -mode mask -mask "pass?d?d?d?d"
```

---

## 📊 Sample Output

```text
[INFO] BitLocker Bruteforce Toolkit by Zwanski Tech
[INFO] Initializing attack with 8 threads
[WARN] Hash extraction is a complex process... This tool does not perform real hash extraction.
[SUCCESS] Created a dummy hash file for demonstration: bitlocker_hash.txt
[INFO] Starting dictionary attack
[HASHCAT] Executing: hashcat -m 22100 -a 0 -o recovered_password.txt --status /path/to/my_hash.txt /path/to/rockyou.txt
[STATUS] Status: Running, Speed: 125.4 kH/s, Progress: 45.2%
[SUCCESS] Password recovered: MySecurePassword123!
[SUCCESS] Results for 1 recovered password(s) saved to bitlocker_results.json
```