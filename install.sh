#!/bin/bash

# FINAL: SYSLOG + API (100% WORKING)
# Using legacy rsyslog syntax for maximum compatibility
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

# Step 2: Install core packages
print_step "Installing rsyslog, MySQL, Apache, PHP..."
apt install -y rsyslog mysql-server apache2 php libapache2-mod-php net-tools ufw curl jq

# Detect PHP version
PHP_VER=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.1")
print_status "PHP Version: $PHP_VER"

# Step 3: Install PHP MySQL extension (PDO)
print_step "Installing php${PHP_VER}-mysql (PDO)..."
apt install -y php${PHP_VER}-mysql
systemctl restart apache2

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

# Step 7: Write rsyslog configuration using legacy format
print_step "Writing 99-custom-mysql.conf (legacy format for compatibility)..."
cat > /etc/rsyslog.d/99-custom-mysql.conf << 'EOF'
# Load required modules
$ModLoad imudp
$ModLoad imtcp
$ModLoad ommysql

# Configure listeners
$InputUDPServerRun 514
$InputTCPServerRun 512
$InputTCPServerRun 513
$InputTCPServerRun 515
$InputTCPServerRun 516
$InputTCPServerRun 517
$InputTCPServerRun 518
$InputTCPServerRun 519
$InputTCPServerRun 520
$InputTCPServerRun 521

# SQL template for database insertion
$template SqlFormat,"INSERT INTO remote_logs (received_at, hostname, facility, message, port) VALUES ('%timegenerated:::date-mysql%', '%hostname%', '%syslogfacility-text%', '%msg%', '%inputname%')",SQL

# Filter and send to MySQL (exclude localhost)
:fromhost, !isequal, "PLACEHOLDER_HOST" :ommysql:localhost,PLACEHOLDER_DB,PLACEHOLDER_USER,PLACEHOLDER_PASS;SqlFormat

# Also log to file
:fromhost, !isequal, "PLACEHOLDER_HOST" /var/log/remote_syslog.log

# Stop processing for remote logs
& stop
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

# Step 9: Secure MySQL installation
print_step "Securing MySQL..."
mysql_secure_installation <<EOF

n
y
y
y
y
EOF

# Step 10: Configure MySQL
print_step "Setting up MySQL database and user..."
sed -i 's/127.0.0.1/0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
systemctl restart mysql

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
    port VARCHAR(50),
    INDEX idx_id (id),
    INDEX idx_received_at (received_at),
    INDEX idx_hostname (hostname)
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
  "facility": "optional-facility-filter"
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

## Testing

Run the test script:
```bash
bash /var/www/html/api/test.sh
```

## Manual Test

```bash
curl -X POST http://localhost/api/api.php \
  -H "Content-Type: application/json" \
  -d '{"secret_key": "your-key", "limit": 10}'
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