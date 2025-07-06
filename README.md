# Linux Security & Administration Guide

[![Linux Security](https://img.shields.io/badge/Linux-Security-red?style=for-the-badge&logo=linux)](https://github.com/gotr00t0day)
[![System Admin](https://img.shields.io/badge/System-Administration-blue?style=for-the-badge&logo=gnu-bash)](https://www.linux.org)
[![Open Source](https://img.shields.io/badge/Open-Source-green?style=for-the-badge&logo=opensource)](https://www.kernel.org)

## Table of Contents

1. [Introduction](#introduction)
2. [Linux Security Fundamentals](#linux-security-fundamentals)
3. [User & Permission Management](#user--permission-management)
4. [Firewall Configuration](#firewall-configuration)
5. [System Hardening Techniques](#system-hardening-techniques)
6. [Log Analysis & SIEM Integration](#log-analysis--siem-integration)
7. [Intrusion Detection Systems](#intrusion-detection-systems)
8. [Container Security](#container-security)
9. [Kernel Security & SELinux](#kernel-security--selinux)
10. [Network Security Configuration](#network-security-configuration)
11. [Incident Response & Forensics](#incident-response--forensics)
12. [Backup & Recovery](#backup--recovery)
13. [Monitoring & Alerting](#monitoring--alerting)
14. [Security Automation](#security-automation)
15. [Compliance & Auditing](#compliance--auditing)
16. [Resources](#resources)

---

## Introduction

Linux Security & Administration encompasses the practices, tools, and methodologies needed to secure Linux systems in enterprise environments. This guide provides comprehensive coverage of security hardening, monitoring, and incident response for Linux-based infrastructure.

### Key Objectives
- **Implement Defense in Depth**: Multiple layers of security controls
- **Minimize Attack Surface**: Reduce potential entry points
- **Enable Continuous Monitoring**: Real-time threat detection
- **Ensure Compliance**: Meet regulatory requirements

---

## Linux Security Fundamentals

### Linux Security Architecture

#### Linux Security Model
```
User Space
├── Applications
├── System Libraries
├── System Calls Interface
└── Hardware Abstraction Layer
Kernel Space
├── Process Management
├── Memory Management
├── File System
├── Network Stack
└── Device Drivers
```

#### Core Security Components
- **Discretionary Access Control (DAC)**: File permissions and ownership
- **Mandatory Access Control (MAC)**: SELinux, AppArmor policies
- **Access Control Lists (ACLs)**: Extended permissions
- **Capabilities**: Fine-grained privilege control

### Security Assessment Commands
```bash
# System information
uname -a
lsb_release -a
cat /etc/os-release

# Security modules
ls /sys/kernel/security/
cat /proc/version

# Kernel parameters
sysctl -a | grep -E "(kernel|net|fs)" | grep -v "^#"

# Security-related packages
dpkg -l | grep -E "(security|audit|apparmor|selinux)"
```

---

## User & Permission Management

### User Account Security

#### User Management Best Practices
```bash
# Create user with specific shell and home directory
useradd -m -s /bin/bash -c "Security Analyst" analyst
passwd analyst

# Lock/unlock user accounts
usermod -L analyst  # Lock
usermod -U analyst  # Unlock

# Set password policies
chage -M 90 -m 1 -W 7 analyst  # Max 90 days, min 1 day, warn 7 days
chage -l analyst  # View password aging info

# Disable user account
usermod -s /sbin/nologin analyst
```

#### Sudo Configuration
```bash
# Edit sudoers file safely
visudo

# Example sudoers configurations
# Allow user to run specific commands as root
analyst ALL=(root) /usr/bin/systemctl, /usr/bin/journalctl

# Allow group to run commands without password
%wheel ALL=(ALL) NOPASSWD: ALL

# Restrict commands with parameters
analyst ALL=(root) /usr/bin/systemctl start apache2, /usr/bin/systemctl stop apache2

# Log sudo activity
Defaults log_host, log_year, logfile="/var/log/sudo.log"
```

### File Permissions and ACLs

#### Standard Permissions
```bash
# Set secure permissions on sensitive files
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
chmod 700 /root
chmod 755 /home

# Special permissions
chmod u+s /usr/bin/sudo  # SUID
chmod g+s /usr/bin/write  # SGID
chmod +t /tmp  # Sticky bit

# Find files with special permissions
find / -perm -4000 -type f 2>/dev/null  # SUID files
find / -perm -2000 -type f 2>/dev/null  # SGID files
find / -perm -1000 -type d 2>/dev/null  # Sticky bit directories
```

#### Extended ACLs
```bash
# Install ACL tools
apt-get install acl  # Debian/Ubuntu
yum install acl      # RHEL/CentOS

# Set ACLs
setfacl -m u:analyst:r-- /etc/shadow
setfacl -m g:security:rw- /var/log/security.log
setfacl -m d:u:analyst:rw- /secure/  # Default ACL for directory

# View ACLs
getfacl /etc/shadow

# Remove ACLs
setfacl -x u:analyst /etc/shadow
setfacl -b /etc/shadow  # Remove all ACLs
```

---

## Firewall Configuration

### iptables Configuration

#### Basic iptables Rules
```bash
# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (change port as needed)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

#### Advanced iptables Rules
```bash
# Rate limiting for SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP

# Block common attack patterns
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# GeoIP blocking (requires xtables-addons)
iptables -A INPUT -m geoip --src-cc CN,RU,KP -j DROP

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "
iptables -A INPUT -j DROP
```

### UFW (Uncomplicated Firewall)

#### UFW Basic Configuration
```bash
# Enable UFW
ufw enable

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow specific services
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp

# Allow from specific IP
ufw allow from 192.168.1.100

# Allow specific port range
ufw allow 8000:8010/tcp

# Delete rules
ufw delete allow ssh
ufw --numbered  # Show numbered rules
ufw delete 2    # Delete rule number 2

# Advanced rules
ufw allow from 192.168.1.0/24 to any port 22
ufw deny from 10.0.0.0/8
```

### firewalld Configuration

#### firewalld Basic Setup
```bash
# Start and enable firewalld
systemctl start firewalld
systemctl enable firewalld

# Check status
firewall-cmd --state
firewall-cmd --list-all

# Set default zone
firewall-cmd --set-default-zone=public

# Add services to zone
firewall-cmd --zone=public --add-service=ssh --permanent
firewall-cmd --zone=public --add-service=http --permanent
firewall-cmd --zone=public --add-service=https --permanent

# Add custom port
firewall-cmd --zone=public --add-port=8080/tcp --permanent

# Reload configuration
firewall-cmd --reload

# Rich rules
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" accept' --permanent
```

---

## System Hardening Techniques

### Kernel Hardening

#### Sysctl Security Parameters
```bash
# Create security configuration file
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Hide kernel pointers
kernel.kptr_restrict = 2

# Control access to dmesg
kernel.dmesg_restrict = 1

# Restrict access to kernel logs
kernel.kmesg_restrict = 1
EOF

# Apply settings
sysctl -p /etc/sysctl.d/99-security.conf
```

### Service Hardening

#### Disable Unnecessary Services
```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# Disable unnecessary services
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable bluetooth
systemctl disable nfs-server
systemctl disable rpcbind

# Remove unnecessary packages
apt-get purge telnet ftp rsh-client rsh-redone-client

# Check for listening ports
netstat -tuln
ss -tuln
```

#### SSH Hardening
```bash
# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# SSH security configuration
cat >> /etc/ssh/sshd_config << 'EOF'
# Change default port
Port 2222

# Protocol version
Protocol 2

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
PubkeyAuthentication yes

# Disable empty passwords
PermitEmptyPasswords no

# Login grace time
LoginGraceTime 60

# Max authentication tries
MaxAuthTries 3

# Max sessions
MaxSessions 2

# Client alive settings
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable X11 forwarding
X11Forwarding no

# Disable user environment
PermitUserEnvironment no

# Allowed users/groups
AllowUsers analyst admin
AllowGroups ssh-users

# Host-based authentication
HostbasedAuthentication no
IgnoreRhosts yes

# Disable tunneled clear text passwords
ChallengeResponseAuthentication no

# Kerberos and GSSAPI
KerberosAuthentication no
GSSAPIAuthentication no
EOF

# Test SSH config
sshd -t

# Restart SSH service
systemctl restart sshd
```

---

## Log Analysis & SIEM Integration

### Centralized Logging

#### Rsyslog Configuration
```bash
# Configure rsyslog for centralized logging
cat > /etc/rsyslog.d/50-security.conf << 'EOF'
# Security-related logs
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
mail.*                          /var/log/mail.log
user.*                          /var/log/user.log

# Remote logging to SIEM
*.* @@siem.company.com:514

# High priority messages to console
*.emerg                         :omusrmsg:*

# Security alerts
auth.crit                       /var/log/security-alerts.log
EOF

# Restart rsyslog
systemctl restart rsyslog
```

#### Log Rotation
```bash
# Configure logrotate for security logs
cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log
/var/log/kern.log
/var/log/security-alerts.log
{
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
```

### Log Analysis Scripts

#### Security Log Analysis
```bash
#!/bin/bash
# security-analysis.sh

echo "=== Security Log Analysis ==="
echo "Date: $(date)"
echo ""

# Failed SSH attempts
echo "=== Failed SSH Login Attempts ==="
grep "Failed password" /var/log/auth.log | tail -10

# Successful SSH logins
echo "=== Successful SSH Logins ==="
grep "Accepted password\|Accepted publickey" /var/log/auth.log | tail -10

# Sudo usage
echo "=== Sudo Usage ==="
grep "sudo:" /var/log/auth.log | tail -10

# Root login attempts
echo "=== Root Login Attempts ==="
grep "root" /var/log/auth.log | grep -E "(Failed|Accepted)" | tail -10

# New user accounts
echo "=== New User Accounts ==="
grep "useradd" /var/log/auth.log | tail -10

# File permission changes
echo "=== File Permission Changes ==="
grep "chmod\|chown" /var/log/kern.log | tail -10
```

### SIEM Integration

#### ELK Stack Integration
```bash
# Install Filebeat for log shipping
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.5.0-linux-x86_64.tar.gz
tar xzvf filebeat-8.5.0-linux-x86_64.tar.gz

# Configure Filebeat
cat > filebeat.yml << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/kern.log
    - /var/log/syslog
    - /var/log/security-alerts.log
  fields:
    logtype: security
    environment: production

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "security-logs-%{+yyyy.MM.dd}"

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
EOF

# Start Filebeat
./filebeat -e
```

---

## Intrusion Detection Systems

### AIDE (Advanced Intrusion Detection Environment)

#### AIDE Configuration
```bash
# Install AIDE
apt-get install aide

# Configure AIDE
cat > /etc/aide/aide.conf << 'EOF'
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# File selection rules
/bin f+p+u+g+s+b+m+c+md5+sha1
/sbin f+p+u+g+s+b+m+c+md5+sha1
/usr/bin f+p+u+g+s+b+m+c+md5+sha1
/usr/sbin f+p+u+g+s+b+m+c+md5+sha1
/etc f+p+u+g+s+b+m+c+md5+sha1
/root f+p+u+g+s+b+m+c+md5+sha1

# Exclude temporary directories
!/tmp
!/var/tmp
!/proc
!/sys
!/dev
EOF

# Initialize AIDE database
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run AIDE check
aide --check

# Automate AIDE checks
cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report $(hostname)" admin@company.com
EOF

chmod +x /etc/cron.daily/aide
```

### Tripwire Configuration

#### Tripwire Setup
```bash
# Install Tripwire
apt-get install tripwire

# Configure Tripwire policy
cat > /etc/tripwire/twpol.txt << 'EOF'
(
  rulename = "Tripwire Binaries",
  severity = $(SIG_HI)
)
{
  $(TWBIN)/siggen                      -> $(SEC_BIN) ;
  $(TWBIN)/tripwire                    -> $(SEC_BIN) ;
  $(TWBIN)/twadmin                     -> $(SEC_BIN) ;
  $(TWBIN)/twprint                     -> $(SEC_BIN) ;
}

(
  rulename = "Critical system boot files",
  severity = 100
)
{
  /boot                                -> $(SEC_CRIT) ;
  /lib/modules                         -> $(SEC_CRIT) ;
}
EOF

# Update Tripwire policy
tripwire --update-policy /etc/tripwire/twpol.txt

# Initialize database
tripwire --init

# Run integrity check
tripwire --check
```

### OSSEC HIDS

#### OSSEC Configuration
```bash
# Download and install OSSEC
wget https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
tar -xzf 3.7.0.tar.gz
cd ossec-hids-3.7.0
./install.sh

# Configure OSSEC
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <syscheck>
    <frequency>7200</frequency>
    <directories check_all="yes">/bin,/sbin</directories>
    <directories check_all="yes">/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/etc</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
  </syscheck>

  <rootcheck>
    <frequency>7200</frequency>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
</ossec_config>
EOF

# Start OSSEC
/var/ossec/bin/ossec-control start
```

---

## Container Security

### Docker Security

#### Docker Daemon Hardening
```bash
# Configure Docker daemon securely
cat > /etc/docker/daemon.json << 'EOF'
{
  "icc": false,
  "userns-remap": "default",
  "log-driver": "syslog",
  "disable-legacy-registry": true,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
EOF

# Restart Docker
systemctl restart docker
```

#### Container Security Best Practices
```bash
# Run containers as non-root user
docker run --user 1000:1000 nginx

# Use read-only root filesystem
docker run --read-only nginx

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Set resource limits
docker run -m 512m --cpus="1.5" nginx

# Use security profiles
docker run --security-opt apparmor:nginx-profile nginx
docker run --security-opt seccomp:seccomp-profile.json nginx

# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy nginx:latest
```

### Kubernetes Security

#### Pod Security Standards
```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

#### Network Policies
```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-traffic
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 80
```

---

## Kernel Security & SELinux

### SELinux Configuration

#### SELinux Basics
```bash
# Check SELinux status
sestatus
getenforce

# Set SELinux mode
setenforce 1  # Enforcing
setenforce 0  # Permissive

# Make permanent change
sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# View SELinux contexts
ls -Z /home/
ps -eZ
```

#### SELinux Policy Management
```bash
# List SELinux booleans
getsebool -a

# Set SELinux boolean
setsebool -P httpd_can_network_connect on

# Create custom SELinux policy
# Generate policy template
sepolicy generate --application /usr/local/bin/myapp

# Compile and install policy
make -f /usr/share/selinux/devel/Makefile
semodule -i myapp.pp

# Check SELinux denials
sealert -a /var/log/audit/audit.log
```

### AppArmor Configuration

#### AppArmor Profile Management
```bash
# Install AppArmor utilities
apt-get install apparmor-utils

# Check AppArmor status
aa-status

# Create AppArmor profile
aa-genprof /usr/bin/myapp

# Edit profile
cat > /etc/apparmor.d/usr.bin.myapp << 'EOF'
#include <tunables/global>

/usr/bin/myapp {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/bin/myapp mr,
  /etc/myapp.conf r,
  /var/log/myapp.log w,
  /tmp/ rw,
  /tmp/** rw,
}
EOF

# Load profile
apparmor_parser -r /etc/apparmor.d/usr.bin.myapp

# Set profile to enforce mode
aa-enforce /usr/bin/myapp
```

---

## Network Security Configuration

### Network Monitoring

#### Network Traffic Analysis
```bash
# Monitor network connections
netstat -tuln
ss -tuln

# Monitor network traffic
tcpdump -i eth0 -n
wireshark

# Network flow analysis
nfcapd -w -D -p 9995 -B 1048576 -l /var/cache/nfcapd
nfdump -R /var/cache/nfcapd -s srcip -n 10
```

#### Intrusion Detection with Suricata
```bash
# Install Suricata
apt-get install suricata

# Configure Suricata
cat > /etc/suricata/suricata.yaml << 'EOF'
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

rule-files:
  - emerging-threats.rules
  - local.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
EOF

# Update rules
suricata-update

# Start Suricata
systemctl start suricata
systemctl enable suricata
```

---

## Incident Response & Forensics

### Incident Response Procedures

#### Initial Response Script
```bash
#!/bin/bash
# incident-response.sh

INCIDENT_DIR="/tmp/incident-$(date +%Y%m%d-%H%M%S)"
mkdir -p $INCIDENT_DIR

echo "=== Incident Response Data Collection ==="
echo "Timestamp: $(date)" > $INCIDENT_DIR/timestamp.txt

# System information
uname -a > $INCIDENT_DIR/system-info.txt
uptime > $INCIDENT_DIR/uptime.txt
who > $INCIDENT_DIR/logged-users.txt

# Process information
ps aux > $INCIDENT_DIR/processes.txt
pstree > $INCIDENT_DIR/process-tree.txt

# Network information
netstat -tuln > $INCIDENT_DIR/network-listening.txt
netstat -tun > $INCIDENT_DIR/network-connections.txt
arp -a > $INCIDENT_DIR/arp-table.txt

# File system information
mount > $INCIDENT_DIR/mounted-filesystems.txt
df -h > $INCIDENT_DIR/disk-usage.txt
lsof > $INCIDENT_DIR/open-files.txt

# Log files
cp /var/log/auth.log $INCIDENT_DIR/
cp /var/log/syslog $INCIDENT_DIR/
cp /var/log/kern.log $INCIDENT_DIR/

# Memory dump (if volatility tools available)
if command -v linpmem &> /dev/null; then
    linpmem $INCIDENT_DIR/memory-dump.raw
fi

echo "Incident response data collected in: $INCIDENT_DIR"
```

### Forensics Tools

#### Disk Imaging and Analysis
```bash
# Create disk image
dd if=/dev/sda of=/mnt/evidence/disk-image.dd bs=4096 conv=noerror,sync
md5sum /mnt/evidence/disk-image.dd > /mnt/evidence/disk-image.md5

# Mount image read-only
mount -o ro,loop /mnt/evidence/disk-image.dd /mnt/analysis

# File carving with Foremost
foremost -t all -i /mnt/evidence/disk-image.dd -o /mnt/analysis/carved

# Timeline analysis
fls -r -m C: /mnt/evidence/disk-image.dd > /mnt/analysis/timeline.body
mactime -b /mnt/analysis/timeline.body -d > /mnt/analysis/timeline.csv
```

#### Memory Analysis
```bash
# Install Volatility
pip install volatility3

# Memory analysis commands
python3 vol.py -f memory-dump.raw windows.info
python3 vol.py -f memory-dump.raw windows.pslist
python3 vol.py -f memory-dump.raw windows.netscan
python3 vol.py -f memory-dump.raw windows.filescan
python3 vol.py -f memory-dump.raw windows.malfind
```

---

## Resources

### Essential Tools
- **Nmap**: Network discovery and security auditing
- **Wireshark**: Network protocol analyzer
- **AIDE**: File integrity monitoring
- **OSSEC**: Host-based intrusion detection
- **Suricata**: Network intrusion detection
- **ClamAV**: Antivirus engine
- **Fail2ban**: Intrusion prevention system

### Documentation
- [Linux Security HOWTO](https://tldp.org/HOWTO/Security-HOWTO/)
- [Red Hat Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/)
- [Ubuntu Security](https://help.ubuntu.com/community/Security)
- [CIS Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

### Training Resources
- [Linux Foundation Security Training](https://training.linuxfoundation.org/training/cybersecurity/)
- [SANS Linux Security](https://www.sans.org/courses/linux-security/)
- [Linux Academy Security Courses](https://linuxacademy.com/course/category/security)

---

## Conclusion

Linux security requires a comprehensive approach combining preventive measures, monitoring, and incident response capabilities. This guide provides the foundation for securing Linux systems in enterprise environments.

Key takeaways:
- **Layer security controls** for defense in depth
- **Monitor continuously** for threats and anomalies  
- **Automate where possible** to reduce human error
- **Stay updated** with security patches and best practices
- **Test configurations** before production deployment

---

*This guide is for educational and authorized security administration purposes only. Always follow your organization's policies and procedures.*

[![GitHub](https://img.shields.io/badge/GitHub-gotr00t0day-black?style=for-the-badge&logo=github)](https://github.com/gotr00t0day)
[![Website](https://img.shields.io/badge/Website-gotr00t0day.github.io-blue?style=for-the-badge&logo=web)](https://gotr00t0day.github.io) 
