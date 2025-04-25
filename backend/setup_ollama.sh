#!/bin/bash

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "Ollama is not installed. Please install it first."
    echo "Visit https://ollama.ai/download for installation instructions."
    exit 1
fi

# Pull the ALIENTELLIGENCE/predictivethreatdetection model
echo "Pulling ALIENTELLIGENCE/predictivethreatdetection model..."
ollama pull ALIENTELLIGENCE/predictivethreatdetection

# If the model doesn't exist, create it with a custom modelfile
if [ $? -ne 0 ]; then
    echo "Model not found in registry. Creating custom model..."
    
    # Create a modelfile
    cat > Modelfile << EOL
FROM llama3
SYSTEM You are ALIENTELLIGENCE/predictivethreatdetection, an advanced cybersecurity AI assistant specializing in threat detection, vulnerability assessment, and security analysis. You provide detailed, technical responses about cybersecurity topics, focusing on actionable insights and practical recommendations. You maintain a serious, professional tone appropriate for security professionals.
EOL
    
    # Create the model
    ollama create ALIENTELLIGENCE/predictivethreatdetection -f Modelfile
    
    # Clean up
    rm Modelfile
fi

echo "Setup complete. The model is ready to use."
