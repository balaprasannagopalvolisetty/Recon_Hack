#!/bin/bash

# Check if backup directory is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

BACKUP_DIR="$1"

# Check if backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    echo "Backup directory $BACKUP_DIR does not exist"
    exit 1
fi

# Stop containers
echo "Stopping containers..."
docker-compose down

# Restore data volumes
echo "Restoring data volumes..."
docker run --rm -v recon-tool_backend_data:/target -v $(pwd)/$BACKUP_DIR:/backup alpine sh -c "rm -rf /target/* && tar -xzf /backup/backend_data.tar.gz -C /target"
docker run --rm -v recon-tool_ollama_data:/target -v $(pwd)/$BACKUP_DIR:/backup alpine sh -c "rm -rf /target/* && tar -xzf /backup/ollama_data.tar.gz -C /target"
docker run --rm -v recon-tool_certbot_data:/target -v $(pwd)/$BACKUP_DIR:/backup alpine sh -c "rm -rf /target/* && tar -xzf /backup/certbot_data.tar.gz -C /target"

# Restore configuration files
echo "Restoring configuration files..."
cp -r $BACKUP_DIR/nginx .
cp $BACKUP_DIR/.env . 2>/dev/null || echo "No .env file found in backup"

# Start containers
echo "Starting containers..."
docker-compose up -d

echo "Restore completed successfully from $BACKUP_DIR"
