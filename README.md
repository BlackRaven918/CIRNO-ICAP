# CIRNO-ICAP
CIRNO-ICAP is an ICAP server that can inspect web traffic received from proxies like Squid, it does not come included with Squid, you need to install that yourself.

## Requirements

**All testing was done on an Ubuntu 24.04 machine.**

- Python 3.12 needs to be installed
- Pip needs to be installed
- Python3-venv needs to be installed

## Install guide

To install this server, you need to clone this repository to your machine. Then you need to create a virtual environment in the root directory of this repository: `python -m venv venv`. After that you need to activatte the virtual environment.
Linux: `source venv/bin/activate` .
Then you need to install the required packages with `pip install -r requirements.txt`

After that you need to install the ClamAV daemon on your server.
```bash
sudo apt install clamav clamav-daemon -y
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
```
And download the signatures

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam```
