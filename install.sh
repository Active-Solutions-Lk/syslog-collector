#!/bin/bash

# FINAL: SYSLOG + API (100% WORKING)
# Using legacy rsyslog syntax with proper port tracking
# Compatible with rsyslog 8.x

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

# Step 1: Update system
print_step "Updating system..."
apt update -y

# Step 2: Detect OS and install appropriate database
print_step "Detecting operating system..."
if [ -f /etc/debian_version ]; then
    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
    if [ "$DEBIAN_VERSION" -ge "12" ]; then
        print_status "Debian $DEBIAN_VERSION detected - using MariaDB"
        DB_PACKAGE="mariadb-server"
    else
        print_status "Debian $DEBIAN_VERSION detected - using MySQL"
        DB_PACKAGE="mysql-server"
    fi
elif [ -f /etc/lsb-release ]; then
    print_status "Ubuntu detected - using MySQL"
    DB_PACKAGE="mysql-server"
else
    print_warning "Unknown OS - defaulting to MySQL"
    DB_PACKAGE="mysql-server"
fi

print_step "Installing rsyslog, $DB_PACKAGE, Apache, PHP..."
apt install -y rsyslog $DB_PACKAGE apache2 php libapache2-mod-php net-tools ufw curl jq

# Detect PHP version
PHP_VER=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.1")
print_status "PHP Version: $PHP_VER"

# Step 3: Install PHP MySQL extension (PDO)
print_step "Installing php${PHP_VER}-mysql (PDO)..."
apt install -y php${PHP_VER}-mysql

# Check if port 80 is in use before starting Apache
print_step "Checking port 80 availability..."
if netstat -tuln | grep -q ":80 "; then
    print_warning "Port 80 is already in use. Checking what's using it..."
    PROCESS=$(lsof -i :80 2>/dev/null | grep LISTEN | awk '{print $1}' | head -1)
    if [ -n "$PROCESS" ]; then
        print_status "Process using port 80: $PROCESS"
        if [ "$PROCESS" = "apache2" ] || [ "$PROCESS" = "httpd" ]; then
            print_status "Apache is already running, restarting it..."
            systemctl restart apache2
        else
            print_error "Port 80 is used by $PROCESS. Please stop it first:"
            print_error "  sudo systemctl stop $PROCESS"
            print_error "  or: sudo pkill -9 $PROCESS"
            lsof -i :80 2>/dev/null | grep LISTEN
            exit 1
        fi
    fi
else
    systemctl restart apache2
fi

# Step 4: Verify PDO installation
print_step "Verifying PDO..."
if php -r "exit(in_array('mysql', PDO::getAvailableDrivers()) ? 0 : 1);" 2>/dev/null; then
    print_status "PDO OK"
else
    print_error "PDO installation failed"
    exit 1
fi

# Step 5: Enable and start rsyslog
print_step "Enabling rsyslog..."
systemctl enable rsyslog
systemctl start rsyslog

# Step 6: Install rsyslog-mysql module
print_step "Installing rsyslog-mysql (for ommysql module)..."
apt install -y rsyslog-mysql

# Block rsyslog-mysql auto-configuration
print_step "Blocking rsyslog-mysql auto-config..."
echo "# BLOCKED BY install.sh" > /etc/rsyslog.d/mysql.conf

# Step 7: Write rsyslog configuration using legacy format with port tracking
print_step "Writing 99-custom-mysql.conf (with proper port tracking)..."
cat > /etc/rsyslog.d/99-custom-mysql.conf << 'EOF'
# Load required modules
$ModLoad imudp
$ModLoad imtcp
$ModLoad ommysql

# Configure listeners with unique names
$InputUDPServerBindRuleset udp_514
$UDPServerRun 514

$InputTCPServerBindRuleset tcp_512
$InputTCPServerRun 512

$InputTCPServerBindRuleset tcp_513
$InputTCPServerRun 513

$InputTCPServerBindRuleset tcp_515
$InputTCPServerRun 515

$InputTCPServerBindRuleset tcp_516
$InputTCPServerRun 516

$InputTCPServerBindRuleset tcp_517
$InputTCPServerRun 517

$InputTCPServerBindRuleset tcp_518
$InputTCPServerRun 518

$InputTCPServerBindRuleset tcp_519
$InputTCPServerRun 519

$InputTCPServerBindRuleset tcp_520
$InputTCPServerRun 520

$InputTCPServerBindRuleset tcp_521
$InputTCPServerRun 521

# SQL templates for each port
$template SqlFormat514,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '514')",SQL
$template SqlFormat512,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '512')",SQL
$template SqlFormat513,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '513')",SQL
$template SqlFormat515,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '515')",SQL
$template SqlFormat516,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '516')",SQL
$template SqlFormat517,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '517')",SQL
$template SqlFormat518,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '518')",SQL
$template SqlFormat519,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '519')",SQL
$template SqlFormat520,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '520')",SQL
$template SqlFormat521,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '521')",SQL

# Ruleset for UDP 514
$RuleSet udp_514
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat514
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 512
$RuleSet tcp_512
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat512
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 513
$RuleSet tcp_513
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat513
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 515
$RuleSet tcp_515
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat515
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 516
$RuleSet tcp_516
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat516
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 517
$RuleSet tcp_517
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat517
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 518
$RuleSet tcp_518
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat518
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 519
$RuleSet tcp_519
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat519
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 520
$RuleSet tcp_520
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat520
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Ruleset for TCP 521
$RuleSet tcp_521
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat521
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log
& stop

# Switch back to default ruleset
$RuleSet RSYSLOG_DefaultRuleset
EOF

# Inject configuration variables
print_step "Injecting variables into config..."
sed -i "s|PLACEHOLDER_HOST|$EXCLUDE_HOST|g" /etc/rsyslog.d/99-custom-mysql.conf
sed -i "s|PLACEHOLDER_DB|$DB_NAME|g" /etc/rsyslog.d/99-custom-mysql.conf
sed -i "s|PLACEHOLDER_USER|$DB_USER|g" /etc/rsyslog.d/99-custom-mysql.conf
sed -i "s|PLACEHOLDER_PASS|$DB_PASS|g" /etc/rsyslog.d/99-custom-mysql.conf

# Step 8: Configure firewall
print_step "Opening firewall ports..."
ufw allow 514/udp
for p in 512 513 515 516 517 518 519 520 521; do 
    ufw allow $p/tcp
done
ufw allow 80/tcp

# Step 9: Secure MySQL/MariaDB installation
print_step "Securing $DB_PACKAGE..."
if command -v mysql_secure_installation >/dev/null 2>&1; then
    mysql_secure_installation <<EOF

n
y
y
y
y
EOF
else
    print_warning "mysql_secure_installation not found, skipping..."
fi

# Step 10: Configure MySQL/MariaDB
print_step "Setting up database and user..."

# Find the MySQL/MariaDB config file
if [ -f /etc/mysql/mariadb.conf.d/50-server.cnf ]; then
    MYSQL_CONF="/etc/mysql/mariadb.conf.d/50-server.cnf"
elif [ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]; then
    MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
else
    print_warning "MySQL config file not found, skipping bind-address change"
    MYSQL_CONF=""
fi

if [ -n "$MYSQL_CONF" ]; then
    print_status "Configuring $MYSQL_CONF"
    sed -i 's/127.0.0.1/0.0.0.0/g' "$MYSQL_CONF"
fi

# Restart database service
if systemctl list-units --type=service | grep -q mariadb; then
    systemctl restart mariadb
else
    systemctl restart mysql
fi

# Create database, table, and user
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME;
USE $DB_NAME;

CREATE TABLE IF NOT EXISTS remote_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    received_at DATETIME,
    hostname VARCHAR(255),
    facility VARCHAR(50),
    message TEXT,
    port VARCHAR(10),
    INDEX idx_id (id),
    INDEX idx_received_at (received_at),
    INDEX idx_hostname (hostname),
    INDEX idx_port (port)
);

CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

print_status "Database and user created successfully"

# Step 11: Validate and restart rsyslog
print_step "Validating rsyslog configuration..."
if rsyslogd -N1 2>&1 | grep -q "error"; then
    print_error "Rsyslog config validation FAILED"
    rsyslogd -N1
    echo "Check the config at: /etc/rsyslog.d/99-custom-mysql.conf"
    exit 1
else
    print_status "Rsyslog config is VALID"
fi

print_step "Restarting rsyslog..."
systemctl restart rsyslog
sleep 2

if systemctl is-active --quiet rsyslog; then
    print_status "Rsyslog restarted successfully"
else
    print_error "Rsyslog failed to start"
    systemctl status rsyslog --no-pager
    exit 1
fi

# Step 12: Create API directory and files
print_step "Creating API..."
rm -rf "$API_DIR" /var/www/html/syslog-collector-api-new 2>/dev/null || true
mkdir -p "$API_DIR"
chown www-data:www-data "$API_DIR"

# Create connection.php
cat > "$API_DIR/connection.php" << EOF
<?php
/**
 * Database Connection Configuration
 */
define('DB_HOST', 'localhost');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('DB_NAME', '$DB_NAME');
define('API_SECRET_KEY', '$API_SECRET_KEY');

/**
 * Get database connection
 * @return PDO|null
 */
function getDBConnection() {
    try {
        \$pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        \$pdo->exec("SET NAMES utf8mb4");
        return \$pdo;
    } catch (Exception \$e) {
        error_log("DB Connection Error: " . \$e->getMessage());
        return null;
    }
}

/**
 * Validate API key
 * @param string \$key
 * @return bool
 */
function validateAPIKey(\$key) {
    return hash_equals(API_SECRET_KEY, \$key);
}
?>
EOF

# Create api.php
cat > "$API_DIR/api.php" << 'EOF'
<?php
/**
 * Syslog API Endpoint
 * Retrieves logs from the database
 */
require_once 'connection.php';

// Set JSON response header
header('Content-Type: application/json');

// Get input
$input = json_decode(file_get_contents('php://input'), true);

// Validate API key
if (!$input || !validateAPIKey($input['secret_key'] ?? '')) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'Invalid or missing API key'
    ]);
    exit;
}

// Get database connection
$pdo = getDBConnection();
if (!$pdo) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Database connection error'
    ]);
    exit;
}

// Get parameters
$limit = min(1000, max(1, (int)($input['limit'] ?? 100)));
$last_id = max(0, (int)($input['last_id'] ?? 0));
$hostname = $input['hostname'] ?? null;
$facility = $input['facility'] ?? null;
$port = $input['port'] ?? null;

// Build query
$query = "SELECT * FROM remote_logs WHERE id > ?";
$params = [$last_id];

if ($hostname) {
    $query .= " AND hostname = ?";
    $params[] = $hostname;
}

if ($facility) {
    $query .= " AND facility = ?";
    $params[] = $facility;
}

if ($port) {
    $query .= " AND port = ?";
    $params[] = $port;
}

$query .= " ORDER BY id ASC LIMIT ?";
$params[] = $limit;

// Execute query
try {
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $logs = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $logs,
        'count' => count($logs),
        'last_id' => $last_id,
        'next_id' => $logs ? end($logs)['id'] : $last_id
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Query error: ' . $e->getMessage()
    ]);
}
?>
EOF

# Create test script
cat > "$API_DIR/test.sh" << EOF
#!/bin/bash
echo "=========================================="
echo "Testing Syslog API"
echo "=========================================="
echo ""
echo "Fetching latest 5 logs..."
echo ""
curl -s -X POST http://localhost/api/api.php \\
  -H "Content-Type: application/json" \\
  -d '{
    "secret_key": "$API_SECRET_KEY",
    "limit": 5
  }' | jq .
echo ""
echo "=========================================="
echo ""
echo "Fetching logs from port 514..."
echo ""
curl -s -X POST http://localhost/api/api.php \\
  -H "Content-Type: application/json" \\
  -d '{
    "secret_key": "$API_SECRET_KEY",
    "limit": 5,
    "port": "514"
  }' | jq .
echo ""
echo "=========================================="
EOF
chmod +x "$API_DIR/test.sh"

# Create README
cat > "$API_DIR/README.md" << 'EOF'
# Syslog Collector API

## Endpoints

### POST /api/api.php

Retrieve syslog entries from the database.

#### Request Body
```json
{
  "secret_key": "your-secret-key",
  "limit": 100,
  "last_id": 0,
  "hostname": "optional-hostname-filter",
  "facility": "optional-facility-filter",
  "port": "optional-port-filter"
}
```

#### Response
```json
{
  "success": true,
  "data": [...],
  "count": 10,
  "last_id": 0,
  "next_id": 10
}
```

## Available Ports

- UDP: 514
- TCP: 512, 513, 515, 516, 517, 518, 519, 520, 521

## Testing

Run the test script:
```bash
bash /var/www/html/api/test.sh
```

## Manual Test

```bash
# Get all logs
curl -X POST http://localhost/api/api.php \
  -H "Content-Type: application/json" \
  -d '{"secret_key": "your-key", "limit": 10}'

# Get logs from specific port
curl -X POST http://localhost/api/api.php \
  -H "Content-Type: application/json" \
  -d '{"secret_key": "your-key", "limit": 10, "port": "514"}'
```
EOF

chown www-data:www-data "$API_DIR"/*
print_status "API files created successfully"

# Step 13: Final verification
print_step "Final verification..."
OK=true

# Check rsyslog
if ! systemctl is-active --quiet rsyslog; then
    print_error "Rsyslog is not running"
    OK=false
fi

# Check Apache
if ! systemctl is-active --quiet apache2; then
    print_error "Apache is not running"
    OK=false
fi

# Check MySQL connection
if ! mysql -u "$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME;" >/dev/null 2>&1; then
    print_error "MySQL connection failed"
    OK=false
fi

# Check if ports are listening
if ! netstat -tuln | grep -q ":514 "; then
    print_warning "UDP port 514 may not be listening"
fi

# Final result
echo
if [ "$OK" = true ]; then
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}           ✓ INSTALLATION COMPLETE!            ${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    print_status "Server IP: $(hostname -I | awk '{print $1}')"
    print_status "API Endpoint: http://$(hostname -I | awk '{print $1}')/api/api.php"
    print_status "API Key: $API_SECRET_KEY"
    echo
    print_status "Listening on:"
    print_status "  - UDP: 514"
    print_status "  - TCP: 512, 513, 515-521"
    echo
    print_status "Database:"
    print_status "  - Name: $DB_NAME"
    print_status "  - User: $DB_USER"
    print_status "  - Table: remote_logs"
    echo
    print_status "Test API: bash $API_DIR/test.sh"
    print_status "View logs: tail -f /var/log/remote_syslog.log"
    print_status "Check MySQL: mysql -u $DB_USER -p'$DB_PASS' -e 'SELECT * FROM $DB_NAME.remote_logs LIMIT 5;'"
    echo
    print_status "Port tracking is now enabled - each log will show the correct port number!"
    echo
    echo -e "${GREEN}================================================${NC}"
else
    echo
    echo -e "${RED}================================================${NC}"
    echo -e "${RED}        ✗ INSTALLATION FAILED                   ${NC}"
    echo -e "${RED}================================================${NC}"
    echo
    print_error "Some services failed to start properly"
    echo
    print_status "Check logs:"
    print_status "  - Rsyslog: journalctl -u rsyslog -n 50"
    print_status "  - Apache: journalctl -u apache2 -n 50"
    print_status "  - MySQL: journalctl -u mysql -n 50"
    echo
    exit 1
fi