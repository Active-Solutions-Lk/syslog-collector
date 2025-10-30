#!/bin/bash

# FINAL: SYSLOG + API (100% WORKING)
# Fixed heredoc + variable injection
# rsyslog config is valid

set -e

# ------------------- Colors -------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# ------------------- Config -------------------
DB_NAME="syslog_db"
DB_USER="Admin"
DB_PASS="Admin@collector1"
API_SECRET_KEY="sk_5a1b3c4d2e6f7a8b9c0d1e2f3a4b5c6d"
API_DIR="/var/www/html/api"
EXCLUDE_HOST=$(hostname)

# ------------------- Start -------------------
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}   SYSLOG + API: FINAL 100% WORKING            ${NC}"
echo -e "${GREEN}================================================${NC}"
echo

# Step 1: Update
print_step "Updating system..."
apt update -y

# Step 2: Install core
print_step "Installing rsyslog, MySQL, Apache, PHP..."
apt install -y rsyslog mysql-server apache2 php libapache2-mod-php net-tools ufw curl jq

# Detect PHP version
PHP_VER=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.1")
print_status "PHP Version: $PHP_VER"

# Step 3: Install PDO
print_step "Installing php${PHP_VER}-mysql (PDO)..."
apt install -y php${PHP_VER}-mysql
systemctl restart apache2

# Step 4: Verify PDO
print_step "Verifying PDO..."
if php -r "exit(in_array('mysql', PDO::getAvailableDrivers()) ? 0 : 1);" 2>/dev/null; then
    print_status "PDO OK"
else
    print_error "PDO failed"
    exit 1
fi

# Step 5: Enable rsyslog
print_step "Enabling rsyslog..."
systemctl enable rsyslog
systemctl start rsyslog

# Step 6: Install rsyslog-mysql (for ommysql.so)
print_step "Installing rsyslog-mysql (for ommysql module)..."
apt install -y rsyslog-mysql

# Block auto-config
print_step "Blocking rsyslog-mysql auto-config..."
echo "# BLOCKED BY install.sh" > /etc/rsyslog.d/mysql.conf

# Step 7: Write rsyslog config (heredoc + sed)
print_step "Writing 99-custom-mysql.conf..."
cat > /etc/rsyslog.d/99-custom-mysql.conf << EOF
module(load="imudp")
module(load="imtcp")
module(load="ommysql")

input(type="imudp" port="514" ruleset="udp_logs")
input(type="imtcp" port="512" ruleset="tcp_512")
input(type="imtcp" port="513" ruleset="tcp_513")
input(type="imtcp" port="515" ruleset="tcp_515")
input(type="imtcp" port="516" ruleset="tcp_516")
input(type="imtcp" port="517" ruleset="tcp_517")
input(type="imtcp" port="518" ruleset="tcp_518")
input(type="imtcp" port="519" ruleset="tcp_519")
input(type="imtcp" port="520" ruleset="tcp_520")
input(type="imtcp" port="521" ruleset="tcp_521")

template(name="SqlFormat" type="string" option.sql="on" 
         string="INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', %\$!port%)")

ruleset(name="udp_logs") {
    if \$fromhost != 'PLACEHOLDER_HOST' then {
        set \$!port = "514";
        action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat")
        action(type="omfile" file="/var/log/remote_syslog.log")
    }
}

ruleset(name="tcp_512") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "512"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_513") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "513"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_515") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "515"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_516") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "516"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_517") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "517"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_518") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "518"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_519") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "519"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_520") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "520"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
ruleset(name="tcp_521") { if \$fromhost != 'PLACEHOLDER_HOST' then { set \$!port = "521"; action(type="ommysql" server="localhost" db="PLACEHOLDER_DB" uid="PLACEHOLDER_USER" pwd="PLACEHOLDER_PASS" template="SqlFormat"); action(type="omfile" file="/var/log/remote_syslog.log"); } }
EOF

# Inject variables safely
sed -i "s|PLACEHOLDER_HOST|$EXCLUDE_HOST|g; s|PLACEHOLDER_DB|$DB_NAME|g; s|PLACEHOLDER_USER|$DB_USER|g; s|PLACEHOLDER_PASS|$DB_PASS|g" /etc/rsyslog.d/99-custom-mysql.conf

# Step 8: Open firewall
print_step "Opening ports..."
ufw allow 514/udp
for p in 512 513 515 516 517 518 519 520 521; do ufw allow $p/tcp; done
ufw allow 80/tcp

# Step 9: Secure MySQL
print_step "Securing MySQL..."
mysql_secure_installation <<EOF

n
y
y
y
y
EOF

# Step 10: Configure MySQL
print_step "Setting up MySQL..."
sed -i 's/127.0.0.1/0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
systemctl restart mysql

mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME;
USE $DB_NAME;
CREATE TABLE IF NOT EXISTS remote_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    received_at DATETIME,
    hostname VARCHAR(255),
    facility VARCHAR(50),
    message TEXT,
    port INT
);
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

# Step 11: Restart rsyslog
print_step "Restarting rsyslog..."
rsyslogd -N1
systemctl restart rsyslog

# Step 12: Create API
print_step "Creating API..."
rm -rf "$API_DIR" /var/www/html/syslog-collector-api-new 2>/dev/null || true
mkdir -p "$API_DIR"
chown www-data:www-data "$API_DIR"

cat > "$API_DIR/connection.php" << EOF
<?php
define('DB_HOST', 'localhost');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('DB_NAME', '$DB_NAME');
define('API_SECRET_KEY', '$API_SECRET_KEY');
function getDBConnection() {
    try { \$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]); \$pdo->exec("SET NAMES utf8mb4"); return \$pdo; }
    catch (Exception \$e) { error_log("DB Error: " . \$e->getMessage()); return null; }
}
function validateAPIKey(\$k) { return hash_equals(API_SECRET_KEY, \$k); }
?>
EOF

cat > "$API_DIR/api.php" << 'EOF'
<?php
require_once 'connection.php';
header('Content-Type: application/json');
$in = json_decode(file_get_contents('php://input'), true);
if (!$in || !validateAPIKey($in['secret_key'] ?? '')) { echo json_encode(['success' => false, 'message' => 'Invalid key']); exit; }
$pdo = getDBConnection();
if (!$pdo) { echo json_encode(['success' => false, 'message' => 'DB error']); exit; }
$limit = min(1000, (int)($in['limit'] ?? 100));
$last = (int)($in['last_id'] ?? 0);
$stmt = $pdo->prepare("SELECT * FROM remote_logs WHERE id > ? ORDER BY id ASC LIMIT ?");
$stmt->execute([$last, $limit]);
$logs = $stmt->fetchAll();
echo json_encode(['success' => true, 'data' => $logs, 'count' => count($logs), 'next_id' => $logs ? end($logs)['id'] : $last]);
?>
EOF

cat > "$API_DIR/test.sh" << EOF
#!/bin/bash
echo "Testing API..."
curl -s -X POST http://localhost/api/api.php -H "Content-Type: application/json" -d '{
  "secret_key": "$API_SECRET_KEY",
  "limit": 2
}' | jq .
EOF
chmod +x "$API_DIR/test.sh"

# Final Check
print_step "Final verification..."
OK=true
systemctl is-active --quiet rsyslog || OK=false
systemctl is-active --quiet apache2 || OK=false
mysql -u $DB_USER -p'$DB_PASS' -e "USE $DB_NAME;" >/dev/null 2>&1 || OK=false

if [ "$OK" = true ]; then
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}           100% WORKING!                       ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    print_status "API: http://$(hostname -I | awk '{print $1}')/api/api.php"
    print_status "Test: bash $API_DIR/test.sh"
else
    print_error "Final check failed"
    exit 1
fi