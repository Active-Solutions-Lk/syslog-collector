#!/bin/bash

# FINAL: SYSLOG + API (100% WORKING)
# Fixed rsyslog syntax - using compact action format
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
DB_PASS="Admin@collector1