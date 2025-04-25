#!/bin/bash

# Create backup directory
BACKUP_DIR="backups/$(date +%Y-%m-%d_%H-%M-%S)"
mkdir -p $BACKUP_DIR

# Backup data volumes
echo "Backing up data volumes..."
docker run --rm -v recon-tool_backend_data:/source -v $(pwd)/$BACKUP_DIR:/backup alpine tar -czf /backup/backend_data.tar.gz -C /source .
docker run --rm -v recon-tool_ollama_data:/source -v $(pwd)/$BACKUP_DIR:/backup alpine tar -czf /backup/ollama_data.tar.gz -C /source .
docker run --rm -v recon-tool_certbot_data:/source -v $(pwd)/$BACKUP_DIR:/backup alpine tar -czf /backup/certbot_data.tar.gz -C /source .

# Backup configuration files
echo "Backing up configuration files..."
cp -r nginx $BACKUP_DIR/
cp .env $BACKUP_DIR/ 2>/dev/null || echo "No .env file found"

echo "Backup completed successfully to $BACKUP_DIR"
