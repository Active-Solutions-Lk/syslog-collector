#!/bin/bash

# FULL SYSLOG + API INSTALLER
# Combines: rsyslog collector + API
# One command: sudo bash install.sh
# No input, no conflicts, 100% automated

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
echo -e "${GREEN}   SYSLOG COLLECTOR + API - ONE-CLICK SETUP    ${NC}"
echo -e "${GREEN}================================================${NC}"
echo

# Step 1: Update
print_step "Updating system..."
apt update -y

# Step 2: Install core (rsyslog, mysql, apache, php)
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

# Step 6: Configure rsyslog (50-mysql.conf)
print_step "Configuring rsyslog for MySQL + ports..."
cat > /etc/rsyslog.d/50-mysql.conf << EOF
module(load="imudp")
module(load="imtcp")
module(load="ommysql")

input(type="imudp" port="514" ruleset="udp_logs")
$(for p in 512 513 515 516 517 518 519 520 521; do echo "input(type=\"imtcp\" port=\"$p\" ruleset=\"tcp_$p\")"; done)

template(name="SqlFormat" type="string" option.sql="on" 
         string="INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', %\$!port%)")

ruleset(name="udp_logs") {
    if \$fromhost != '$EXCLUDE_HOST' then {
        set \$!port = "514";
        action(type="ommysql" server="localhost" db="$DB_NAME" uid="$DB_USER" pwd="$DB_PASS" template="SqlFormat")
        action(type="omfile" file="/var/log/remote_syslog.log")
    }
}
$(for p in 512 513 515 516 517 518 519 520 521; do
cat << INNER
ruleset(name="tcp_$p") {
    if \$fromhost != '$EXCLUDE_HOST' then {
        set \$!port = "$p";
        action(type="ommysql" server="localhost" db="$DB_NAME" uid="$DB_USER" pwd="$DB_PASS" template="SqlFormat")
        action(type="omfile" file="/var/log/remote_syslog.log")
    }
}
INNER
done)
EOF

# Step 7: Open firewall
print_step "Opening syslog ports..."
ufw allow 514/udp
for p in 512 513 515 516 517 518 519 520 521; do ufw allow $p/tcp; done
ufw allow 80/tcp

# Step 8: Secure MySQL
print_step "Securing MySQL (non-interactive)..."
mysql_secure_installation <<EOF

n
y
y
y
y
EOF

# Step 9: Configure MySQL remote + create DB
print_step "Setting up MySQL database and user..."
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

# Step 10: Install rsyslog-mysql
print_step "Installing rsyslog-mysql..."
apt install -y rsyslog-mysql

# Step 11: Restart rsyslog
print_step "Restarting rsyslog..."
rsyslogd -N1
systemctl restart rsyslog

# Step 12: Create API
print_step "Creating API at $API_DIR..."
rm -rf "$API_DIR" /var/www/html/syslog-collector-api-new 2>/dev/null || true
mkdir -p "$API_DIR"
chown www-data:www-data "$API_DIR"

# connection.php
cat > "$API_DIR/connection.php" << EOF
<?php
define('DB_HOST', 'localhost');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('DB_NAME', '$DB_NAME');
define('API_SECRET_KEY', '$API_SECRET_KEY');

function getDBConnection() {
    try {
        \$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
        \$pdo->exec("SET NAMES utf8mb4");
        return \$pdo;
    } catch (Exception \$e) {
        error_log("DB Error: " . \$e->getMessage());
        return null;
    }
}
function validateAPIKey(\$k) { return hash_equals(API_SECRET_KEY, \$k); }
?>
EOF

# api.php
cat > "$API_DIR/api.php" << 'EOF'
<?php
require_once 'connection.php';
header('Content-Type: application/json');
$in = json_decode(file_get_contents('php://input'), true);
if (!$in || !validateAPIKey($in['secret_key'] ?? '')) {
    echo json_encode(['success' => false, 'message' => 'Invalid key']); exit;
}
$p = get_getDBConnection();
if (!$conn) { echo json_encode(['success' => false, 'message' => 'DB error']); exit; }
$limit = min(1000, (int)($in['limit'] ?? 100));
$last = (int)($in['last_id'] ?? 0);
$stmt = $conn->prepare("SELECT * FROM remote_logs WHERE id > ? ORDER BY id ASC LIMIT ?");
$stmt->execute([$last, $limit]);
$logs = $stmt->fetchAll();
echo json_encode([
    'success' => true,
    'data' => $logs,
    'count' => count($logs),
    'next_id' => $logs ? end($logs)['id'] : $last
]);
?>
EOF

# test script
cat > "$API_DIR/test.sh" << EOF
#!/bin/bash
curl -s -X POST http://localhost/api/api.php -H "Content-Type: application/json" -d '{
  "secret_key": "$API_SECRET_KEY",
  "limit": 2
}' | jq .
EOF
chmod +x "$API_DIR/test.sh"

# Final
print_step "Final check..."
OK=true
systemctl is-active --quiet rsyslog || OK=false
systemctl is-active --quiet apache2 || OK=false
mysql -u $DB_USER -p'$DB_PASS' -e "USE $DB_NAME;" >/dev/null 2>&1 || OK=false

if [ "$OK" = true ]; then
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}        FULL SETUP COMPLETE!                   ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    print_status "API: http://$(hostname -I | awk '{print $1}')/api/api.php"
    print_status "Test: bash $API_DIR/test.sh"
    print_status "Logs: /var/log/remote_syslog.log"
else
    print_error "Something failed"
    exit 1
fi