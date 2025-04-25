"use client"

import { Progress } from "@/components/ui/progress"
import { Code, Network, Folder, Shield, PiIcon as Api, FileCode, Cloud, Loader2, Globe, Mail } from "lucide-react"

interface ScanProgressProps {
  progress: number
  currentModule: string
}

export const ScanProgress = ({ progress, currentModule }: ScanProgressProps) => {
  const getModuleIcon = (moduleId: string) => {
    switch (moduleId) {
      case "domain_dns":
        return Globe
      case "tech_stack":
        return Code
      case "ports_network":
        return Network
      case "files_directories":
        return Folder
      case "api_endpoints":
        return Api
      case "js_analysis":
        return FileCode
      case "cloud_security":
        return Cloud
      case "vulnerabilities":
        return Shield
      case "email_credentials":
        return Mail
      default:
        return Loader2
    }
  }

  const getModuleName = (moduleId: string) => {
    switch (moduleId) {
      case "domain_dns":
        return "Domain & DNS"
      case "tech_stack":
        return "Technology Stack"
      case "ports_network":
        return "Ports & Network"
      case "files_directories":
        return "Files & Directories"
      case "api_endpoints":
        return "API & Endpoints"
      case "js_analysis":
        return "JavaScript Analysis"
      case "cloud_security":
        return "Cloud Security"
      case "vulnerabilities":
        return "Vulnerabilities"
      case "email_credentials":
        return "Email & Credentials"
      default:
        return "Initializing..."
    }
  }

  const Icon = currentModule ? getModuleIcon(currentModule) : Loader2

  return (
    <div className="terminal w-full max-w-3xl mx-auto p-6 animate-pulse-slow">
      <div className="flex items-center mb-4">
        <Icon className="h-6 w-6 text-green-500 mr-2 animate-spin" />
        <h3 className="text-lg font-medium text-green-500 cyber-glow">
          Scanning: {currentModule ? getModuleName(currentModule) : "Initializing..."}
        </h3>
      </div>

      <div className="space-y-2">
        <div className="flex justify-between text-sm text-green-400">
          <span>Progress</span>
          <span>{progress}%</span>
        </div>
        <Progress value={progress} className="h-2 bg-green-900/30" indicatorClassName="bg-green-500" />
      </div>

      <div className="mt-4 typing-effect text-sm text-green-400 w-full">
        Analyzing target... Extracting data... Identifying vulnerabilities...
      </div>
    </div>
  )
}
