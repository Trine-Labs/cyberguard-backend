#!/bin/sh
# ============================================================================
# CyberGuard — Automated PostgreSQL Backup Script
# Runs pg_dump inside the Docker container and stores compressed backups
# with 7-day retention on the VPS.
#
# Usage:
#   chmod +x /root/cyberguard/backup_db.sh
#   # Add to crontab: 0 3 * * * /root/cyberguard/backup_db.sh >> /root/cyberguard/backups/cron.log 2>&1
# ============================================================================

BACKUP_DIR="/root/cyberguard/backups"
CONTAINER="cyberguard_postgres"
DB_NAME="cyberguard_db"
DB_USER="cyberguard"
RETENTION_DAYS=7
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="cyberguard_backup_${TIMESTAMP}.sql.gz"

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

echo "[$(date)] Starting database backup..."

# Run pg_dump inside the container and compress output
docker exec "${CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

if [ $? -eq 0 ]; then
    SIZE=$(du -sh "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    echo "[$(date)] ✓ Backup completed: ${BACKUP_FILE} (${SIZE})"
else
    echo "[$(date)] ✗ Backup FAILED!"
    exit 1
fi

# Remove backups older than retention period
DELETED=$(find "${BACKUP_DIR}" -name "cyberguard_backup_*.sql.gz" -mtime +${RETENTION_DAYS} -delete -print | wc -l)
echo "[$(date)] Cleaned up ${DELETED} old backup(s) (>${RETENTION_DAYS} days)"

echo "[$(date)] Backup complete."
