# ReconAI - Advanced Web Reconnaissance Tool

<div align="center">
  <img src="public/images/recon-ai-logo.png" alt="ReconAI Logo" width="200"/>
  <h3>OLLAMA - Based Vulnerability Detection and Analysis</h3>
</div>

## 🎬 Demo

### Demo Video
To view the full demo video, [click here](https://youtu.be/wG8XAazgHD8)

## 📋 Overview

ReconAI is an advanced web reconnaissance tool that combines traditional security scanning with AI-powered analysis to provide comprehensive insights into web application security. It helps security professionals, penetration testers, and developers identify vulnerabilities, misconfigurations, and potential security risks in web applications.

## ✨ Key Features

- **Comprehensive Scanning Modules**:
  - Domain & DNS Analysis
  - Technology Stack Detection
  - Ports & Network Scanning
  - Files & Directories Discovery
  - API Endpoints Analysis
  - JavaScript Analysis
  - Cloud Security Assessment
  - Vulnerability Detection
  - Email & Credentials Exposure

- **AI-Powered Analysis**:
  - Interactive AI chat interface
  - Contextual security recommendations
  - Vulnerability prioritization
  - Threat intelligence integration
  - Natural language query support

- **Advanced Reporting**:
  - Detailed PDF reports
  - Customizable report sections
  - Executive summaries
  - Technical details
  - Remediation recommendations

- **Modern UI/UX**:
  - Responsive design
  - Real-time scan progress
  - Interactive dashboards
  - Visualization of findings
  - Dark mode support

## 🛠️ Technology Stack

- **Frontend**: Next.js, React, Tailwind CSS, shadcn/ui
- **Backend**: FastAPI, Python
- **AI/ML**: Ollama, LLM integration
- **Database**: File-based storage (JSON)
- **Infrastructure**: Docker, Nginx, Let's Encrypt
- **Security**: HTTPS, API key authentication, role-based access

## 🚀 Getting Started

### Prerequisites

- Docker and Docker Compose
- Domain name (for production deployment)
- API keys (optional):
  - Shodan API key
  - VirusTotal API key
  - NVD API key
  - OpenAI API key

### Local Development Setup

1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/yourusername/recon-ai.git
   cd recon-ai
   \`\`\`

2. Create a `.env` file with your API keys:
   \`\`\`bash
   SHODAN_API_KEY=your_shodan_api_key
   VT_API_KEY=your_virustotal_api_key
   NVD_API_KEY=your_nvd_api_key
   OPENAI_API_KEY=your_openai_api_key
   \`\`\`

3. Start the development environment:
   \`\`\`bash
   docker-compose up -d
   \`\`\`

4. Access the application at `http://localhost:3000`

### Production Deployment

1. Update your domain in the configuration:
   \`\`\`bash
   ./setup-domain.sh your-domain.com
   \`\`\`

2. Set up SSL certificates:
   \`\`\`bash
   ./setup-ssl.sh
   \`\`\`

3. Start the production environment:
   \`\`\`bash
   docker-compose up -d
   \`\`\`

4. Access the application at `https://your-domain.com`

## 📊 Usage

1. **Start a Scan**:
   - Enter a target domain or URL
   - Select the scanning modules to run
   - Enable/disable AI analysis
   - Click "Scan"

2. **View Results**:
   - Navigate through different tabs to view scan results
   - Explore findings by category
   - Check vulnerability details
   - Review AI-generated analysis

3. **Interact with AI**:
   - Ask questions about scan results
   - Request security recommendations
   - Inquire about specific vulnerabilities
   - Get remediation advice

4. **Generate Reports**:
   - Select modules to include
   - Generate PDF report
   - Download and share with stakeholders

## 🔒 Security Considerations

- Only scan domains you own or have explicit permission to scan
- Be aware of legal implications of security scanning
- Respect rate limits of target systems
- Handle discovered sensitive information responsibly
- Keep your API keys secure

## 🧩 Project Structure

\`\`\`
recon-ai/
├── app/                  # Next.js frontend application
├── backend/              # FastAPI backend application
├── components/           # React components
├── lib/                  # Utility functions
├── nginx/                # Nginx configuration
├── public/               # Static assets
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile.frontend   # Frontend Docker configuration
├── setup.sh              # Setup script
└── README.md             # Project documentation
\`\`\`

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [Ollama](https://ollama.ai/) for the LLM integration
- [Shodan](https://www.shodan.io/) for network intelligence
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [NVD](https://nvd.nist.gov/) for vulnerability data
- [shadcn/ui](https://ui.shadcn.com/) for UI components
- [Tailwind CSS](https://tailwindcss.com/) for styling
- [Next.js](https://nextjs.org/) for the frontend framework
- [FastAPI](https://fastapi.tiangolo.com/) for the backend API

## 📞 Contact

For questions, feedback, or support, please open an issue on GitHub or contact the maintainers directly.

---

<div align="center">
  <p>Made with ❤️ by Your Name/Team</p>
</div>
