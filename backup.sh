#!/bin/bash
# automated_backup.sh
# This script copies the SQLite database into a timestamped archive

# Directory where your docker-compose.yml lives
PROJECT_DIR="/opt/munna_store"
BACKUP_DIR="${PROJECT_DIR}/backups"
DB_FILE="${PROJECT_DIR}/data/users.db"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Timestamp format: YYYY-MM-DD_HH-MM-SS
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILE="${BACKUP_DIR}/users_backup_${TIMESTAMP}.db"

# Safely copy the database using sqlite3 backup API if possible, otherwise simple copy
if command -v sqlite3 > /dev/null; then
    sqlite3 "$DB_FILE" ".backup '$BACKUP_FILE'"
else
    cp "$DB_FILE" "$BACKUP_FILE"
fi

# Keep only the last 14 backups (delete older ones)
ls -t "${BACKUP_DIR}"/users_backup_*.db | tail -n +15 | xargs -r rm --

echo "Backup successful: $BACKUP_FILE"
