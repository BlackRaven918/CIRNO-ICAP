#!/bin/bash

# --- Configuration ---
APP_NAME="CIRNO-ICAP"
INSTALL_DIR="/opt/$APP_NAME"
SERVICE_USER="cirno"
PYTHON_BIN="/usr/bin/python3"

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "--- Starting Installation for $APP_NAME ---"

# 1. Install System Dependencies
echo "Installing system packages..."
apt update
apt install -y python3 python3-pip python3-venv clamav clamav-daemon sed sudo

# 2. Create System User
if id "$SERVICE_USER" &>/dev/null; then
    echo "User $SERVICE_USER already exists."
else
    echo "Creating system user: $SERVICE_USER"
    useradd -r -s /usr/sbin/nologin $SERVICE_USER
fi

# 3. Prepare Installation Directory
echo "Setting up directory at $INSTALL_DIR"
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR/

# Ensure the app can write to its own config and phraselists
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
chmod -R 755 $INSTALL_DIR

# 4. Setup Virtual Environment
echo "Creating Python virtual environment..."
sudo -u $SERVICE_USER $PYTHON_BIN -m venv $INSTALL_DIR/venv
sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --upgrade pip
sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r $INSTALL_DIR/requirements.txt

# 5. Apply the pyicap Patch
echo "Applying pyicap.py collections fix..."
PYICAP_PATH=$(find $INSTALL_DIR/venv/lib -name "pyicap.py")
if [ -f "$PYICAP_PATH" ]; then
    sed -i 's/collections\.Callable/collections.abc.Callable/g' "$PYICAP_PATH"
    echo "Patch applied to $PYICAP_PATH"
else
    echo "Warning: pyicap.py not found, patch skipped."
fi

# 6. Configure ClamAV
echo "Configuring ClamAV..."
systemctl stop clamav-freshclam
freshclam || echo "Freshclam update failed, continuing anyway..."
systemctl start clamav-freshclam
systemctl enable clamav-daemon
systemctl restart clamav-daemon

# Add the service user to the clamav group
usermod -aG clamav $SERVICE_USER

# 7. Setup Sudoers Rule for GUI Reload
# This allows the GUI (running as 'cirno') to restart the ICAP service
echo "Configuring sudoers permissions for service management..."
SUDOERS_FILE="/etc/sudoers.d/cirno-icap"
echo "$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl kill -s USR1 CIRNO-ICAP" > $SUDOERS_FILE
echo "$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart CIRNO-ICAP" >> $SUDOERS_FILE
chmod 440 $SUDOERS_FILE

# 8. Setup Systemd Services
echo "Configuring systemd services..."

install_service() {
    local service_name=$1
    local src_file="$INSTALL_DIR/services/$service_name"
    local dest_file="/etc/systemd/system/$service_name"

    if [ -f "$src_file" ]; then
        # Replace %h/CIRNO-ICAP with /opt/CIRNO-ICAP and inject User/Group
        sed -e "s|%h/CIRNO-ICAP|$INSTALL_DIR|g" \
            -e "/\[Service\]/a User=$SERVICE_USER\nGroup=$SERVICE_USER" \
            -e "s|WantedBy=default.target|WantedBy=multi-user.target|g" \
            "$src_file" > "$dest_file"
        echo "Installed service: $service_name"
    else
        echo "Error: Service file $src_file not found!"
    fi
}

install_service "CIRNO-ICAP.service"
install_service "CIRNO-ICAP-gui.service"

# 9. Reload and Start
echo "Starting services..."
systemctl daemon-reload
systemctl enable CIRNO-ICAP CIRNO-ICAP-gui
systemctl restart CIRNO-ICAP CIRNO-ICAP-gui

echo "--- Installation Complete ---"
