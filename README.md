# CIRNO-ICAP
CIRNO-ICAP is an ICAP server that can inspect web traffic received from proxies like Squid, it does not come included with Squid, you need to install that yourself.

## Requirements

**All testing was done on an Ubuntu 24.04 machine.**

- Python 3.12 needs to be installed
- Pip needs to be installed
- Python3-venv needs to be installed

## Install guide

To install this server, you need to clone this repository to your machine. Then you need to create a virtual environment in the root directory of this repository: `python3 -m venv venv`. After that you need to activatte the virtual environment.
Linux: `source venv/bin/activate` .
Then you need to install the required packages with `pip install -r requirements.txt` or if neccessary `pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt`.

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
sudo systemctl start clamav-freshclam
```

Start the ClamAV daemon
```bash
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
```

Fix a package by doing

```bash
sudo sed -i 's/collections\.Callable/collections.abc.Callable/g' ~/CIRNO-ICAP/venv/lib/python3.12/site-packages/pyicap.py
```

Add CIRNO-ICAP and the web gui as a service.

```bash
sudo cp ./services/CIRNO-ICAP.service /etc/systemd/system/
sudo cp ./services/CIRNO-ICAP-gui.service /etc/systemd/system/
```


```bash
sudo systemctl daemon-reload
sudo systemctl enable CIRNO-ICAP
sudo systemctl enable CIRNO-ICAP-gui
sudo systemctl start CIRNO-ICAP
sudo systemctl start CIRNO-ICAP-gui
```