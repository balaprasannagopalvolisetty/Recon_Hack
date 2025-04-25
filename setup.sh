#!/bin/bash

# Create necessary directories
mkdir -p nginx/conf.d nginx/ssl nginx/www backend/data

# Check if .env file exists, if not create it
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOL
SHODAN_API_KEY=your_shodan_api_key
VT_API_KEY=your_virustotal_api_key
NVD_API_KEY=your_nvd_api_key
OPENAI_API_KEY=your_openai_api_key
EOL
    echo "Please edit the .env file with your actual API keys."
fi

# Initialize Ollama model
echo "Setting up Ollama model..."
docker-compose up -d ollama
sleep 10  # Wait for Ollama to start

# Run the setup script inside the Ollama container
docker-compose exec ollama bash -c "curl -fsSL https://ollama.com/install.sh | sh"
docker-compose exec ollama bash -c "ollama pull ALIENTELLIGENCE/predictivethreatdetection || (echo 'Creating custom model...' && echo 'FROM llama3
SYSTEM You are ALIENTELLIGENCE/predictivethreatdetection, an advanced cybersecurity AI assistant specializing in threat detection, vulnerability assessment, and security analysis. You provide detailed, technical responses about cybersecurity topics, focusing on actionable insights and practical recommendations. You maintain a serious, professional tone appropriate for security professionals.' > Modelfile && ollama create ALIENTELLIGENCE/predictivethreatdetection -f Modelfile && rm Modelfile)"

# Set up SSL certificates with Let's Encrypt
echo "Setting up SSL certificates..."
docker-compose up -d nginx
sleep 5  # Wait for nginx to start

# Get SSL certificate
docker-compose run --rm certbot certonly --webroot --webroot-path=/var/www/html --email admin@gopalvolisetty.com --agree-tos --no-eff-email -d reconai.gopalvolisetty.com

# Start all services
echo "Starting all services..."
docker-compose down
docker-compose up -d

echo "Setup complete! ReconAI should be accessible at https://reconai.gopalvolisetty.com"
echo "Please make sure your domain DNS is pointing to 199.36.158.100"
