"use client"

import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Code, Network, Folder, Shield, PiIcon as Api, FileCode, Cloud, Globe, Mail, Brain } from "lucide-react"

interface ScanOptionsProps {
  selectedModules: string[]
  setSelectedModules: (modules: string[]) => void
  disabled: boolean
  useLLM: boolean
  setUseLLM: (use: boolean) => void
}

const modules = [
  { id: "domain_dns", label: "Domain & DNS", icon: Globe },
  { id: "tech_stack", label: "Technology Stack", icon: Code },
  { id: "ports_network", label: "Ports & Network", icon: Network },
  { id: "files_directories", label: "Files & Directories", icon: Folder },
  { id: "api_endpoints", label: "API & Endpoints", icon: Api },
  { id: "js_analysis", label: "JavaScript Analysis", icon: FileCode },
  { id: "cloud_security", label: "Cloud Security", icon: Cloud },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: Shield },
  { id: "email_credentials", label: "Email & Credentials", icon: Mail },
]

export const ScanOptions = ({ selectedModules, setSelectedModules, disabled, useLLM, setUseLLM }: ScanOptionsProps) => {
  const toggleModule = (moduleId: string) => {
    if (selectedModules.includes(moduleId)) {
      setSelectedModules(selectedModules.filter((id) => id !== moduleId))
    } else {
      setSelectedModules([...selectedModules, moduleId])
    }
  }

  const selectAll = () => {
    setSelectedModules(modules.map((m) => m.id))
  }

  const deselectAll = () => {
    setSelectedModules([])
  }

  return (
    <div className="w-full max-w-4xl mx-auto terminal p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium text-green-500 cyber-glow">Scan Options</h3>
        <div className="space-x-4">
          <button
            onClick={selectAll}
            disabled={disabled}
            className="text-sm text-green-400 hover:text-green-300 disabled:text-gray-500 disabled:cursor-not-allowed terminal-text"
          >
            Select All
          </button>
          <button
            onClick={deselectAll}
            disabled={disabled}
            className="text-sm text-green-400 hover:text-green-300 disabled:text-gray-500 disabled:cursor-not-allowed terminal-text"
          >
            Deselect All
          </button>
        </div>
      </div>

      {/* LLM Toggle */}
      <div className="flex items-center justify-between mb-6 p-3 bg-gray-800/50 rounded-md border border-green-500/20">
        <div className="flex items-center space-x-3">
          <Brain className="h-5 w-5 text-green-500" />
          <div>
            <Label htmlFor="use-llm" className="text-sm font-medium text-green-400">
              Enable AI Analysis
            </Label>
            <p className="text-xs text-green-400/70">When enabled, the system will use LLMs to analyze scan results</p>
          </div>
        </div>
        <Switch
          id="use-llm"
          checked={useLLM}
          onCheckedChange={setUseLLM}
          disabled={disabled}
          className="data-[state=checked]:bg-green-500"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map((module) => {
          const Icon = module.icon
          return (
            <div key={module.id} className="flex items-start space-x-3 cyber-border p-2 rounded">
              <Checkbox
                id={module.id}
                checked={selectedModules.includes(module.id)}
                onCheckedChange={() => toggleModule(module.id)}
                disabled={disabled}
                className="border-green-500 text-green-500"
              />
              <div className="flex items-center space-x-2">
                <Icon className="h-5 w-5 text-green-500" />
                <Label
                  htmlFor={module.id}
                  className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 text-green-400"
                >
                  {module.label}
                </Label>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
