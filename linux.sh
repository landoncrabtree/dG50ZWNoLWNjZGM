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
mkdir -p /ccdc/backups
mkdir -p /ccdc/snapshots
mkdir -p /ccdc/configs

cp ./sshd_config_password.conf /ccdc/configs/sshd_config_password.conf
cp ./sshd_config_key.conf /ccdc/configs/sshd_config_key.conf

cd /ccdc

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Backups ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Snapshots ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Detection ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Update ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Updating package lists..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get update
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf update
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum update
    yum install -y epel-release
fi

# Check if Amazon Linux
if [[ $OS == *"Amazon"* ]]; then
    echo "Amazon Linux detected. Installing EPEL..."
    amazon-linux-extras install epel
fi

# Lynis
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Lynis ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Installing and running Lynis..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install lynis
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S lynis
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install lynis
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install lynis
fi

# Run Lynis
lynis audit system > ./scans/lynis.log
# Output each line of the log file that contains "WARNING" or "ERROR"
echo "Warnings and Errors:"
grep -i "warning\|error" ./scans/lynis.log
echo "View the full log at /ccdc/scans/lynis.log"

# rkHunter
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ rkHunter ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Installing and running rkHunter..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install rkhunter
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S rkhunter
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install rkhunter
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y rkhunter
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ClamAV ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Installing and running ClamAV..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install clamav
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S clamav
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install clamav
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y clamav
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Hardening ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Security checks done! Now moving onto configuration hardening..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Enable firewall
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Firewall ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Installing UFW..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install ufw
    ufw enable
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S ufw
    ufw enable
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install ufw
    ufw enable
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y ufw
    ufw enable
fi

# Ask what ports to open
echo "What ports are needed on this host? (separated by spaces)"
echo "Example: '21 20 80 443 8080'"
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
# https://gist.github.com/islander/ddd3981d30adad69d6e5aed78a2c4e72
# System-wide crontab file and cron job directory. Change these for your system.
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Cron ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Scanning for all root, user, and system cron jobs..."
echo "Investigate any 'root' jobs that are not needed..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
CRONTAB='/etc/crontab'
ANACRONTAB='/etc/anacrontab'
CRONDIR='/etc/cron.d'
# Single tab character. Annoyingly necessary.
tab=$(echo -en "\t")
# Given a stream of crontab lines, exclude non-cron job lines, replace
# whitespace characters with a single space, and remove any spaces from the
# beginning of each line.
function clean_cron_lines() {
    while read line ; do
        echo "${line}" |
            egrep --invert-match '^($|\s*#|\s*[[:alnum:]_]+=)' |
            sed --regexp-extended "s/\s+/ /g" |
            sed --regexp-extended "s/^ //"
    done;
}
# Given a stream of cleaned crontab lines, echo any that don't include the
# run-parts command, and for those that do, show each job file in the run-parts
# directory as if it were scheduled explicitly.
function lookup_run_parts() {
    while read line ; do
        match=$(echo "${line}" | egrep -o 'run-parts (-{1,2}\S+ )*\S+')

        if [[ -z "${match}" ]] ; then
            echo "${line}"
        else
            cron_fields=$(echo "${line}" | cut -f1-6 -d' ')
            cron_job_dir=$(echo  "${match}" | awk '{print $NF}')

            if [[ -d "${cron_job_dir}" ]] ; then
                for cron_job_file in "${cron_job_dir}"/* ; do  # */ <not a comment>
                    [[ -f "${cron_job_file}" ]] && echo "${cron_fields} ${cron_job_file}"
                done
            fi
        fi
    done;
}
# sames as lookup_run_parts, but 5 fields, not 6
function lookup_anacron_parts() {
    while read line ; do
        match=$(echo "${line}" | egrep -o 'run-parts (-{1,2}\S+ )*\S+')

        if [[ -z "${match}" ]] ; then
            echo "${line}"
        else
            cron_fields=$(echo "${line}" | cut -f1-5 -d' ')
            cron_job_dir=$(echo  "${match}" | awk '{print $NF}')

            if [[ -d "${cron_job_dir}" ]] ; then
                for cron_job_file in "${cron_job_dir}"/* ; do  # */ <not a comment>
                    [[ -f "${cron_job_file}" ]] && echo "${cron_fields} ${cron_job_file}"
                done
            fi
        fi
    done;
}
# Temporary file for crontab lines.
temp=$(mktemp) || exit 1
# Add all of the jobs from the system-wide crontab file.
cat "${CRONTAB}" | clean_cron_lines | lookup_run_parts >"${temp}"
# Add all of the jobs from the system-wide cron directory.
cat "${CRONDIR}"/* | clean_cron_lines >>"${temp}"  # */ <not a comment>
# Add each user's crontab (if it exists). Insert the user's name between the
# five time fields and the command.
while read user ; do
    crontab -l -u "${user}" 2>/dev/null |
        clean_cron_lines |
        sed --regexp-extended "s/^((\S+ +){5})(.+)$/\1${user} \3/" >>"${temp}"
done < <(cut --fields=1 --delimiter=: /etc/passwd)
# Output the collected crontab lines. Replace the single spaces between the
# fields with tab characters, sort the lines by hour and minute, insert the
# header line, and format the results as a table.
cat "${temp}" | 
    sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1\t\2\t\3\t\4\t\5\t\6\t\7/" |
    sort --numeric-sort --field-separator="${tab}" --key=2,1 |
    sed "1i\mi\th\td\tm\tw\tuser\tcommand" |
    column -s"${tab}" -t
# Output to file
cat "${temp}" | 
    sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1\t\2\t\3\t\4\t\5\t\6\t\7/" |
    sort --numeric-sort --field-separator="${tab}" --key=2,1 |
    sed "1i\mi\th\td\tm\tw\tuser\tcommand" |
    column -s"${tab}" -t > ./scans/cronjobs.log
rm --force "${temp}"
if [ -f "${ANACRONTAB}" ]
then
    echo ""
    echo "# /etc/anacrontab"
    echo -e "period${tab}command"
    cat "${ANACRONTAB}" | clean_cron_lines | lookup_anacron_parts |
        sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1\t\6/"
    # Output to file
    echo "" >> ./scans/cronjobs.log
    echo "# /etc/anacrontab" >> ./scans/cronjobs.log
    echo -e "period${tab}command" >> ./scans/cronjobs.log
    cat "${ANACRONTAB}" | clean_cron_lines | lookup_anacron_parts |
        sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1\t\6/" >> ./scans/cronjobs.log
fi

# Scan users and check if they have sudo permissions
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Users ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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
# Remove the temporary file
rm --force "${temp_file}"
# Output to file
temp_file=$(mktemp)
# Output to file
echo -e "Username\tSudo Permission" > "${temp_file}" >> users.info
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
column -t -s $'\t' "${temp_file}" >> users.info
# Remove the temporary file
rm --force "${temp_file}"

# Get sudoer users
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Sudoers ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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

# Find SUID / SGID binaries
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ SUID / SGID ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Finding SGUID /SGID binaries..."
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Permissions ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Fixing home directory permissions..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
for user in $(cat /etc/passwd | cut -d: -f1); do
  if [ -d "/home/$user" ]; then
    chown -R "$user:$user" "/home/$user"
  fi
done

# Locking /etc/fstab
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Permissions ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Locking /etc/fstab..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
chown root:root /etc/fstab

# sshd_config security
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ sshd ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Replacing /etc/ssh/sshd_config with a more secure version..."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
# Ask if using password or key authentication
echo "Are you using password ('p') or key authentication ('k')?"
echo "Enter 'p' or 'k'. Enter 's' to skip: "
read auth_type
if [ "$auth_type" = "p" ]; then
    rm --force /etc/ssh/sshd_config
    cp ./configs/sshd_config_password.conf /etc/ssh/sshd_config
elif [ "$auth_type" = "k" ]; then
    rm --force /etc/ssh/sshd_config
    cp ./configs/sshd_config_key.conf /etc/ssh/sshd_config
elif [ "$auth_type" = "s" ]; then
    echo "Skipping..."
else
    echo "Invalid input. Skipping..."
fi
systemctl restart sshd

# Upgrade packages
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Update ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
echo "Upgrading packages... This may take a while."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get upgrade
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Syu
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum upgrade
fi

# Compare snapshots
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ Diff ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
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
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ps aux ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
diff ./snapshots/ps_aux.log ./snapshots/ps_aux_new.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/ps_aux.log ./snapshots/ps_aux_new.log > ps_aux_diff.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ lsmod ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
diff ./snapshots/lsmod.log ./snapshots/lsmod_new.log
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
diff ./snapshots/lsmod.log ./snapshots/lsmod_new.log > lsmod_diff.log
if [ -x "$(command -v ss)" ]; then
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ ss -tunlp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
    diff ./snapshots/ss_tunlp.log ./snapshots/ss_tunlp_new.log
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/ss_tunlp.log ./snapshots/ss_tunlp_new.log > ss_tunlp_diff.log
else
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ netstat -tunlp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~]"
    diff ./snapshots/netstat_tunlp.log ./snapshots/netstat_tunlp_new.log
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    diff ./snapshots/netstat_tunlp.log ./snapshots/netstat_tunlp_new.log > netstat_tunlp_diff.log
fi
