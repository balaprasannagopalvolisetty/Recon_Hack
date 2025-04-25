import os
import json
import requests
from typing import Dict, List, Any, Optional

class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        
    def list_models(self) -> List[Dict[str, Any]]:
        """List available models"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                return response.json().get("models", [])
            else:
                print(f"Error listing models: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"Error listing models: {e}")
            return []
    
    def generate(self, 
                 model: str, 
                 prompt: str, 
                 system: Optional[str] = None,
                 temperature: float = 0.7,
                 max_tokens: int = 2048) -> Dict[str, Any]:
        """Generate a response from the model"""
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            if system:
                payload["system"] = system
                
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload
            )
            
            if response.status_code == 200:
                return {
                    "text": response.json().get("response", ""),
                    "model": model,
                    "finish_reason": "stop"
                }
            else:
                print(f"Error generating response: {response.status_code} - {response.text}")
                return {"text": f"Error: {response.status_code}", "error": True}
        except Exception as e:
            print(f"Error generating response: {e}")
            return {"text": f"Error: {str(e)}", "error": True}
    
    def chat(self, 
             model: str, 
             messages: List[Dict[str, str]],
             temperature: float = 0.7,
             max_tokens: int = 2048) -> Dict[str, Any]:
        """Chat with the model"""
        try:
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload
            )
            
            if response.status_code == 200:
                return {
                    "message": {
                        "role": "assistant",
                        "content": response.json().get("message", {}).get("content", "")
                    },
                    "model": model
                }
            else:
                print(f"Error in chat: {response.status_code} - {response.text}")
                return {"message": {"role": "assistant", "content": f"Error: {response.status_code}"}, "error": True}
        except Exception as e:
            print(f"Error in chat: {e}")
            return {"message": {"role": "assistant", "content": f"Error: {str(e)}"}, "error": True}
    
    def pull_model(self, model: str) -> bool:
        """Pull a model from Ollama library"""
        try:
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model}
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"Error pulling model: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"Error pulling model: {e}")
            return False

# Create a singleton instance
ollama = OllamaClient()
