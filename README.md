# 🧊 CIRNO-ICAP
CIRNO-ICAP is an ICAP server that can inspect web traffic received from proxies like Squid, it does not come included with Squid, you need to install that yourself. The web-GUI is optimized for use with netbird.

## Install guide

## Installation Script Breakdown

The repository includes an automated installation script (`install.sh`) designed to deploy **CIRNO-ICAP** and its accompanying GUI onto a Debian/Ubuntu-based system.

The script automates the provision of system dependencies, security hardening, service configuration, and application initialization.

### Prerequisite

* **Root Privileges:** The script makes deep system-level changes (creating users, editing `/etc`, installing packages) and **must** be executed with `sudo` or as the `root` user.

---

### What the Script Does (Step-by-Step)

### 1. Environment & Dependency Provisioning

* **System Packages:** Updates the package registry and installs required packages via `apt`, including Python 3, `pip`, `virtualenv`, `sed`, `sudo`, and **ClamAV** (antivirus engine).
* **Dedicated System User:** Creates a locked-down, system-level user named `cirno` with no login shell (`/usr/sbin/nologin`) to run the application under the principle of least privilege.

### 2. Logging & Maintenance Setup

* **Logs Directory:** Creates `/var/log/CIRNO-ICAP` and sets ownership to the `cirno` user.
* **Log Rotation:** Automatically provisions a `logrotate` configuration block in `/etc/logrotate.d/` to manage, compress, and cycle application logs daily, keeping a maximum of 14 days of history.

### 3. Application Deployment & Isolation

* **Target Installation:** Creates the deployment directory at `/opt/CIRNO-ICAP` and copies the repository files into it, correcting folder ownership and permissions (`755`).
* **Python Virtual Environment (Venv):** Builds an isolated virtual environment inside `/opt/CIRNO-ICAP/venv` and securely installs Python dependencies listed in `requirements.txt`.

### 4. Compatibility Patches & Antivirus Integration

* **`pyicap` Library Fix:** Automatically scans the virtual environment for the `pyicap.py` dependency file and patches a legacy Python compatibility issue (`collections.Callable` changed to `collections.abc.Callable`).
* **ClamAV Engine Setup:** Triggers an initial virus definition update via `freshclam`, enables the ClamAV daemon to start on system boot, and adds the `cirno` service user to the `clamav` group so it can pass files to the engine seamlessly.

### 5. Privileged Access Rules (Sudoers)

* Generates a custom configuration file in `/etc/sudoers.d/cirno-icap`. This safely grants the low-privileged `cirno` user (which runs the GUI) permission to reload (`kill -s USR1`) and restart the backend ICAP daemon via `systemctl` **without requiring a password**.

### 6. Systemd Service Registration

* Extracts service files from the repository (`CIRNO-ICAP.service` and `CIRNO-ICAP-gui.service`), dynamically injects the appropriate installation paths and user permissions, and moves them to `/etc/systemd/system/`.
* Reloads the `systemd` daemon, configures both the ICAP server and the GUI to launch automatically on system boot, and starts both services immediately.

---

## Quick Usage

To run the installation pipeline, navigate to the root of the project directory and execute:

```bash
chmod +x install.sh
sudo ./install.sh

```
