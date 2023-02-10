#!/bin/bash

# This script is meant to be used on a Linux host.
# It will install and run various security tools and harden the system.
# It will also create multiple output files for log and information gathering.

# Author: @landoncrabtree
# Date Feb 9, 2023

# Make sure script is being executed with superuser privileges.
# If not root, then exit.
if [[ "${UID}" -ne 0 ]]
then
  echo "Please run with sudo or as root."
  exit 1
fi

# Create all necessary directories
mkdir -p /ccdc
mkdir -p /ccdc/scans
mkdir -p /ccdc/scans/bash
mkdir -p /ccdc/backups
mkdir -p /ccdc/snapshots
mkdir -p /ccdc/configs
mkdir -p /ccdc/cron

cp ./sshd_config_password.conf /ccdc/configs/sshd_config_password.conf
cp ./sshd_config_key.conf /ccdc/configs/sshd_config_key.conf

cd /ccdc

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Backups ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Backing up some critical files so we can revert if needed..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
mkdir -p /ccdc/backups/etc
mkdir -p /ccdc/backups/etc/ssh
cp /etc/passwd ./backups/etc/passwd.bak
cp /etc/shadow ./backups/etc/shadow.bak
cp /etc/group ./backups/etc/group.bak
cp /etc/gshadow ./backups/etc/gshadow.bak
cp /etc/sudoers ./backups/etc/sudoers.bak
cp /etc/hosts ./backups/etc/hosts.bak
cp /etc/hostname ./backups/etc/hostname.bak
cp /etc/resolv.conf ./backups/etc/resolv.conf.bak
cp /etc/sysctl.conf ./backups/etc/sysctl.conf.bak
cp /etc/fstab ./backups/etc/fstab.bak
cp /etc/issue ./backups/etc/issue.bak
cp /etc/issue.net ./backups/etc/issue.net.bak
cp /etc/ssh/sshd_config ./backups/etc/ssh/sshd_config.bak
cp /etc/ssh/ssh_config ./backups/etc/ssh/ssh_config.bak
cp /etc/ssh/moduli ./backups/etc/ssh/moduli.bak
cp /etc/ssh/ssh_host_rsa_key ./backups/etc/ssh/ssh_host_rsa_key.bak
cp /etc/ssh/ssh_host_rsa_key.pub ./backups/etc/ssh/ssh_host_rsa_key.pub.bak
cp /etc/ssh/ssh_host_dsa_key ./backups/etc/ssh/ssh_host_dsa_key.bak
cp /etc/ssh/ssh_host_dsa_key.pub ./backups/etc/ssh/ssh_host_dsa_key.pub.bak
cp /etc/ssh/ssh_host_ecdsa_key ./backups/etc/ssh/ssh_host_ecdsa_key.bak
cp /etc/ssh/ssh_host_ecdsa_key.pub ./backups/etc/ssh/ssh_host_ecdsa_key.pub.bak
cp /etc/ssh/ssh_host_ed25519_key ./backups/etc/ssh/ssh_host_ed25519_key.bak
cp /etc/ssh/ssh_host_ed25519_key.pub ./backups/etc/ssh/ssh_host_ed25519_key.pub.bak
cp /etc/ssh/ssh_host_key ./backups/etc/ssh/ssh_host_key.bak
cp /etc/ssh/ssh_host_key.pub ./backups/etc/ssh/ssh_host_key.pub.bak

# Snapshot processes, modules, and ports
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Snapshots ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Snapshotting a few things before we continue..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
ps aux > ./snapshots/ps_aux.log
lsmod > ./snapshots/lsmod.log
if [ -x "$(command -v ss)" ]; then
    ss -tunlp > ./snapshots/ss_tunlp.log
else
    netstat -tunlp > ./snapshots/netstat_tunlp.log
fi

# Get output of /etc/os-release
OS=""
PKG_MANAGER=""

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Detection ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Detecting OS, package manager, and other system info..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
# get NAME= from /etc/os-release
OS=$(cat /etc/os-release | grep "^NAME=" | cut -d'=' -f2 | tr -d '"')
# get VERSION= from /etc/os-release
VERSION=$(cat /etc/os-release | grep "^VERSION=" | cut -d'=' -f2 | tr -d '"')

echo "Detecting package manager..."
# Look for apt
if [ -x "$(command -v apt)" ]; then
    PKG_MANAGER="apt"
elif [ -x "$(command -v apt-get)" ]; then
    PKG_MANAGER="apt"
# Look for pacman
elif [ -x "$(command -v pacman)" ]; then
    PKG_MANAGER="pacman"
# Look for dnf
elif [ -x "$(command -v dnf)" ]; then
    PKG_MANAGER="dnf"
# Look for yum
elif [ -x "$(command -v yum)" ]; then
    PKG_MANAGER="yum"
fi

# System info
echo "OS: $OS"
echo "Package manager: $PKG_MANAGER"
# Echo to host.info
echo "OS: $OS" > host.info
echo "Package manager: $PKG_MANAGER" >> host.info
# Get hostname
echo "Hostname: $(hostname)" >> host.info
# Get total storage (in GB)
echo "Total storage: $(df -h / | awk 'NR==2 {print $2}')" >> host.info
# Get total memory (in GB)
echo "Total memory: $(free -h | awk 'NR==2 {print $2}')" >> host.info

# Update the list of available packages
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Update ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Updating package lists..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get update -y
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy --noconfirm
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install -y epel-release
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y epel-release
fi

# Check if Amazon Linux
if [[ $OS == *"Amazon"* ]]; then
    echo "Amazon Linux detected. Installing EPEL..."
    amazon-linux-extras install epel
fi

# Lynis
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Lynis ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Installing and running Lynis..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install lynis -y
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S lynis --noconfirm
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install lynis -y
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install lynis -y
fi

# Run Lynis
lynis audit system > ./scans/lynis.log
# Output each line of the log file that contains "WARNING" or "ERROR"
echo "Warnings and Errors:"
grep -i "warning\|error" ./scans/lynis.log
echo "View the full log at /ccdc/scans/lynis.log"

# rkHunter
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ rkHunter ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Installing and running rkHunter..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install rkhunter -y
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S rkhunter --noconfirm
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install rkhunter -y
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install rkhunter -y
fi

# Run rkhunter
echo "Running rkhunter..."
rkhunter --update
rkhunter --propupd
rkhunter --checkall --skip-keypress > ./scans/rkhunter.log
# Output each line of the log file that contains "WARNING" or "ERROR"
echo "Warnings and Errors:"
grep -i "warning\|error" ./scans/rkhunter.log
echo "View the full log at /ccdc/scans/rkhunter.log"

# ClamAV
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ClamAV ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Installing and running ClamAV..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install clamav -y
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S clamav --noconfirm
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install clamav -y
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install clamav -y
fi

# Run ClamAV
echo "Running ClamAV..."
freshclam
clamscan -r / > ./scans/clamav.log
# Output each line of the log file that contains "FOUND"
echo "Warnings and Errors:"
grep -i "found" ./scans/clamav.log
echo "View the full log at /ccdc/scans/clamav.log"

# Hardening stuff
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Hardening ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Security checks done! Now moving onto configuration hardening..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Enable firewall
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Firewall ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Installing UFW..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install ufw -y
    ufw enable
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S ufw --noconfirm
    ufw enable
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install ufw -y
    ufw enable
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install ufw -y
    ufw enable
fi

# Ask what ports to open
echo "What ports are needed on this host? (separated by spaces)"
echo "Example: '20 21 80 443 8080'"
echo "Common Ports for Reference:"
echo "[20] FTP      [21] FTP      [22] SSH"
echo "[23] Telnet   [25] SMTP     [53] DNS"
echo "[80] HTTP     [110] POP3    [143] IMAP"
echo "[443] HTTPS   [3306] MySQL  [8080] HTTP"
read ports

# Open ports
echo "Opening needed ports..."
for port in $ports; do
    ufw allow $port/tcp
done

# Close all other ports
echo "Closing all other ports..."
ufw default deny incoming

# Crontab stuff
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Crontab ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Scanning for all crontab entries..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
# loop through all users
echo "Checking for cron jobs in each user's crontab..."
for user in $(cut -f1 -d: /etc/passwd); do
    # check if the user has a crontab
    if crontab -u $user -l > /dev/null 2>&1; then
        # if so, print the user and their crontab
        echo "Crontab for $user (/var/spool/cron/$user):"
        echo "Crontab for $user (/var/spool/cron/$user):" > ./cron/crontab-$user.log
        crontab -u $user -l
        crontab -u $user -l >> ./cron/crontab-$user.log
    fi
done
# Check for cron jobs in /etc/crontab
echo "Checking for cron jobs in /etc/crontab..."
if [ -f /etc/crontab ]; then
    echo "Cron jobs found in /etc/crontab:"
    echo "Cron jobs found in /etc/crontab:" > ./cron/crontab-etc.log
    cat /etc/crontab
    cat /etc/crontab >> ./cron/crontab-etc.log
else
    echo "No cron jobs found in /etc/crontab."
fi
# Check for cron jobs in /etc/cron.d
echo "Checking for cron jobs in /etc/cron.d..."
if [ -d /etc/cron.d ]; then
    echo "Cron jobs found in /etc/cron.d:"
    echo "Cron jobs found in /etc/cron.d:" > ./cron/cron.d.log
    ls -al /etc/cron.d
    ls -al /etc/cron.d >> ./cron/cron.d.log
else
    echo "No cron jobs found in /etc/cron.d."
fi
# Check for cron jobs in /etc/cron.daily
echo "Checking for cron jobs in /etc/cron.daily..."
if [ -d /etc/cron.daily ]; then
    echo "Cron jobs found in /etc/cron.daily:"
    echo "Cron jobs found in /etc/cron.daily:" > ./cron/cron.daily.log
    ls -al /etc/cron.daily
    ls -al /etc/cron.daily >> ./cron/cron.daily.log
else
    echo "No cron jobs found in /etc/cron.daily."
fi
# Check for cron jobs in /etc/cron.hourly
echo "Checking for cron jobs in /etc/cron.hourly..."
if [ -d /etc/cron.hourly ]; then
    echo "Cron jobs found in /etc/cron.hourly:"
    echo "Cron jobs found in /etc/cron.hourly:" > ./cron/cron.hourly.log
    ls -al /etc/cron.hourly
    ls -al /etc/cron.hourly >> ./cron/cron.hourly.log
else
    echo "No cron jobs found in /etc/cron.hourly."
fi
# Check for cron jobs in /etc/cron.monthly
echo "Checking for cron jobs in /etc/cron.monthly..."
if [ -d /etc/cron.monthly ]; then
    echo "Cron jobs found in /etc/cron.monthly:"
    echo "Cron jobs found in /etc/cron.monthly:" > ./cron/cron.monthly.log
    ls -al /etc/cron.monthly
    ls -al /etc/cron.monthly >> ./cron/cron.monthly.log
else
    echo "No cron jobs found in /etc/cron.monthly."
fi
# Check for cron jobs in /etc/cron.weekly
echo "Checking for cron jobs in /etc/cron.weekly..."
if [ -d /etc/cron.weekly ]; then
    echo "Cron jobs found in /etc/cron.weekly:"
    echo "Cron jobs found in /etc/cron.weekly:" > ./cron/cron.weekly.log
    ls -al /etc/cron.weekly
    ls -al /etc/cron.weekly >> ./cron/cron.weekly.log
else
    echo "No cron jobs found in /etc/cron.weekly."
fi
# Check for cron jobs in /etc/anacrontab
echo "Checking for cron jobs in /etc/anacrontab..."
if [ -f /etc/anacrontab ]; then
    echo "Cron jobs found in /etc/anacrontab:"
    echo "Cron jobs found in /etc/anacrontab:" > ./cron/anacrontab.log
    cat /etc/anacrontab
    cat /etc/anacrontab >> ./cron/anacrontab.log
else
    echo "No cron jobs found in /etc/anacrontab."
fi
# Check for cron jobs in /etc/cron.allow
echo "Checking for cron jobs in /etc/cron.allow..."
if [ -f /etc/cron.allow ]; then
    echo "Cron jobs found in /etc/cron.allow:"
    echo "Cron jobs found in /etc/cron.allow:" > ./cron/cron.allow.log
    cat /etc/cron.allow
    cat /etc/cron.allow >> ./cron/cron.allow.log
else
    echo "No cron jobs found in /etc/cron.allow."
fi
# Check for cron jobs in /etc/cron.deny
echo "Checking for cron jobs in /etc/cron.deny..."
if [ -f /etc/cron.deny ]; then
    echo "Cron jobs found in /etc/cron.deny:"
    echo "Cron jobs found in /etc/cron.deny:" > ./cron/cron.deny.log
    cat /etc/cron.deny
    cat /etc/cron.deny >> ./cron/cron.deny.log
else
    echo "No cron jobs found in /etc/cron.deny."
fi
# Check for cron jobs in /etc/at.allow
echo "Checking for cron jobs in /etc/at.allow..."
if [ -f /etc/at.allow ]; then
    echo "Cron jobs found in /etc/at.allow:"
    echo "Cron jobs found in /etc/at.allow:" > ./cron/at.allow.log
    cat /etc/at.allow
    cat /etc/at.allow >> ./cron/at.allow.log
else
    echo "No cron jobs found in /etc/at.allow."
fi
# Check for cron jobs in /etc/at.deny
echo "Checking for cron jobs in /etc/at.deny..."
if [ -f /etc/at.deny ]; then
    echo "Cron jobs found in /etc/at.deny:"
    echo "Cron jobs found in /etc/at.deny:" > ./cron/at.deny.log
    cat /etc/at.deny
    cat /etc/at.deny >> ./cron/at.deny.log
else
    echo "No cron jobs found in /etc/at.deny."
fi
# Check for cron jobs in /etc/cron
echo "Checking for cron jobs in /etc/cron..."
if [ -d /etc/cron ]; then
    echo "Cron jobs found in /etc/cron:"
    echo "Cron jobs found in /etc/cron:" > ./cron/cron.log
    ls -al /etc/cron
    ls -al /etc/cron >> ./cron/cron.log
else
    echo "No cron jobs found in /etc/cron."
fi

# Scan users and check if they have sudo permissions
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Users ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding all users on the system..."
echo "Look for unusual users who are not required."
echo "Suspicious users can be removed with 'sudo killall -u <username>' and 'sudo userdel <username>'."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Look for unusual users who are not required." > users.info
echo "Suspicious users can be removed with 'sudo killall -u <username>' and 'sudo userdel <username>'." >> users.info
# Create a temporary file to store the results
temp_file=$(mktemp)
# Define the table header
echo -e "Username\tSudo Permission"
echo -e "Username\tSudo Permission" >> users.info
# Loop through all users in the /etc/passwd file
while read -r line; do
  # Extract the username, user ID, and home directory from each line
  username=$(echo "${line}" | cut -d: -f1)
  uid=$(echo "${line}" | cut -d: -f3)
  # Check if the user has sudo permissions
  if [[ $(id -u) -eq 0 ]]; then
    sudo_permission=$(sudo -l -U "${username}" 2>/dev/null | grep "sudo" &>/dev/null; echo $?)
  else
    sudo_permission=$(sudo -l 2>/dev/null | grep "sudo" &>/dev/null; echo $?)
  fi
  # Write the username and sudo permission to the temporary file
  if [[ "${sudo_permission}" -eq 0 ]]; then
    echo -e "${username}\tNo" >> "${temp_file}"
  else
    echo -e "${username}\tYes" >> "${temp_file}"
  fi
done < /etc/passwd
# Format the output into even columns
column -t -s $'\t' "${temp_file}"
column -t -s $'\t' "${temp_file}" >> users.info
# Remove the temporary file
rm --force "${temp_file}"

# Get sudoer users
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Sudoers ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding all sudoers on the system..."
echo "Investigate which binaries the user can run with 'sudo -U <user> -l'. Check for GTFOBins."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Investigate which binaries the user can run with 'sudo -U <user> -l'. Check for GTFOBins." > sudoers.info
all_users=$(cat /etc/passwd | cut -d: -f1)
# Loop through each user
for user in ${all_users[@]}; do
  # Check if the user has sudo permission
  sudo_check=$(sudo -U "$user" -l 2>&1)
  if [[ "$sudo_check" != *"is not allowed to run"* ]]; then
    # If the user has sudo permission, print the username
    echo "$user"
    echo "$user" >> sudoers.info
  fi
done

# Get users with login shells
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Users ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding all users with login shells..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "These users should more than likely have their passwords changed."
echo "These users should more than likely have their passwords changed." >> shells.info
# Get the list of users from /etc/passwd
while IFS=":" read -r user x uid gid gecos home shell; do
  # Check if the user has a login shell
  if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
    # Check if the user has a password or if login is disabled
    password=$(grep ^"$user:" /etc/shadow | cut -d: -f2)
    if [ "$password" != '*' ]; then
      echo "$user"
      echo "$user" >> shells.info
    fi
  fi
done < /etc/passwd

# Get users with empty passwords
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Users ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding users with empty passwords..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "You should probably cross-reference this with the list of users with login shells."
echo "You should probably cross-reference this with the list of users with login shells." > users_no_passwords.info
echo "Users with login shells and empty passwords should have their passwords changed."
echo "Users with login shells and empty passwords should have their passwords changed." >> users_no_passwords.info
# Get the list of users from /etc/passwd
while IFS=":" read -r user x uid gid gecos home shell; do
    # Check if the user has a password or if login is disabled
    password=$(grep ^"$user:" /etc/shadow | cut -d: -f2)
    if [ "$password" != '*' ]; then
      echo "$user"
      echo "$user" >> users_no_passwords.info
    fi
done < /etc/passwd

# Get users bashrc and profile files
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Users ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding users .bashrc and .bash_profile files..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
for user in $(cat /etc/passwd | cut -d: -f1); do
  if [ -f "/home/$user/.bashrc" ]; then
    echo "/home/$user/.bashrc copied to /ccdc/scans/bash/$user.bashrc"
    cat /home/$user/.bashrc > ./scans/bash/$user.bashrc
  fi
  if [ -f "/home/$user/.bash_profile" ]; then
    echo "/home/$user/.bash_profile copied to /ccdc/scans/bash/$user.bash_profile"
    cat /home/$user/.bash_profile > ./scans/bash/$user.bash_profile
  fi
done
if [ -f "/root/.bashrc" ]; then
    echo "/root/.bashrc copied to /ccdc/scans/bash/root.bashrc"
    cat /root/.bashrc > ./scans/bash/root.bashrc
fi
if [ -f "/root/.bash_profile" ]; then
    echo "/root/.bash_profile copied to /ccdc/scans/bash/root.bash_profile"
    cat /root/.bash_profile > ./scans/bash/root.bash_profile
fi

# Find SUID / SGID binaries
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ SUID / SGID ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Finding SUID / SGID binaries..."
echo "Investigate which binaries are SUID / SGID. Check for GTFOBins."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Investigate which binaries are SUID / SGID. Check for GTFOBins." > suidsgid.info
root_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) -user root 2>/dev/null)
for file in $root_files
do
    echo $file
    echo $file >> suidsgid.info
done

# Fix home directory permissions
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Permissions ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Fixing home directory permissions..."
echo "Locking /etc/fstab..."
echo "Restoring umask permissions..."
echo "Fixing cron permissions..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
for user in $(cat /etc/passwd | cut -d: -f1); do
  if [ -d "/home/$user" ]; then
    chown -R "$user:$user" "/home/$user"
  fi
done
# Locking /etc/fstab
chown root:root /etc/fstab
# Restore umask to CIS Benchmark standard of 027
umask 027
# Repair cron permissions to ensure root is owner and group
# Also remove rwx permissions for group and other
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root -R /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root -R /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root -R /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root -R /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root -R /etc/cron.d
chmod og-rwx /etc/cron.d

# https://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/
# /proc/sys/kernel/yama/ptrace_scope

# sshd_config security
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ sshd ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Replacing /etc/ssh/sshd_config with a more secure version..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
# Ask if using password or key authentication
echo "Are you using password ('p') or key authentication ('k')?"
echo "Enter 'p' or 'k'. Enter 's' to skip: "
read auth_type
if [ "$auth_type" = "p" ]; then
    rm --force /etc/ssh/sshd_config
    cp ./configs/sshd_config_password.conf /etc/ssh/sshd_config
    systemctl restart sshd
elif [ "$auth_type" = "k" ]; then
    rm --force /etc/ssh/sshd_config
    cp ./configs/sshd_config_key.conf /etc/ssh/sshd_config
    systemctl restart sshd
elif [ "$auth_type" = "s" ]; then
    echo "Skipping..."
else
    echo "Invalid input. Skipping..."
fi

# sudoers security
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ sudoers ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Modifying /etc/sudoers to be more secure..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Defaults use_pty" | cat - /etc/sudoers > temp && mv temp /etc/sudoers

# Upgrade packages
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Update ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Upgrading packages... This may take a while."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get upgrade -y
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Syu --noconfirm
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf upgrade -y
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum upgrade -y
fi

# Compare snapshots
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Diff ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Comparing earlier snapshots to current state..."
echo "If anything changed, it may be worth investigating further."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
ps aux > ./snapshots/ps_aux_new.log
lsmod > ./snapshots/lsmod_new.log
if [ -x "$(command -v ss)" ]; then
    ss -tunlp > ./snapshots/ss_tunlp_new.log
else
    netstat -tunlp > ./snapshots/netstat_tunlp_new.log
fi
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ps aux ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/ps_aux.log ./snapshots/ps_aux_new.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/ps_aux.log ./snapshots/ps_aux_new.log > ps_aux_diff.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ lsmod ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/lsmod.log ./snapshots/lsmod_new.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/lsmod.log ./snapshots/lsmod_new.log > lsmod_diff.log
if [ -x "$(command -v ss)" ]; then
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ss -tunlp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/ss_tunlp.log ./snapshots/ss_tunlp_new.log
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/ss_tunlp.log ./snapshots/ss_tunlp_new.log > ss_tunlp_diff.log
else
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ netstat -tunlp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/netstat_tunlp.log ./snapshots/netstat_tunlp_new.log
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/netstat_tunlp.log ./snapshots/netstat_tunlp_new.log > netstat_tunlp_diff.log
fi

# Ask about CIS Benchmark
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ CIS Benchmark ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Would you like to run the CIS Benchmark?"
echo "Enter 'y' or 'n': "
read run_cis
if [ "$run_cis" = "y" ]; then
    echo "Running CIS Benchmark..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt-get install python3 -y
        apt-get install python3-pip -y
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        pacman -S python3 --noconfirm
        pacman -S python-pip --noconfirm
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf install python3 -y
        dnf install python3-pip -y
    elif [ "$PKG_MANAGER" = "yum" ]; then
        yum install python3 -y
        yum install python3-pip -y
    fi
    git clone https://github.com/finalduty/cis-benchmarks-audit.git
    cd cis-benchmarks-audit
    python3 cis_audit.py > ../cis_audit-results.log
    echo "CIS Benchmark results saved to /ccdc/cis_audit-results.log"
    echo "Look for checks which are marked as 'Failed'."
elif [ "$run_cis" = "n" ]; then
    echo "Skipping..."
else
    echo "Invalid input. Skipping..."
fi

# Next steps
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Done! ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Done! The script has performed a number of checks and made some changes."
echo "Please check the output of the script (/ccdc) for anything suspicious."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "NEXT STEPS:"
echo "1. Validate that the system is still working as expected. If issues, restore from /ccdc/backups."
echo "2. Check the output of the script (/ccdc) for anything suspicious."
echo "3. Manual investigation of /tmp, /var/tmp, /bin, /usr/bin, etc for files not detected by ClamAV."
echo "4. Check the diff logs for any changes to running processes, loaded modules, or listening ports."
