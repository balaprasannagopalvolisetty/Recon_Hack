"use client"

import { useState } from "react"
import { TargetInput } from "./target-input"
import { ScanProgress } from "./scan-progress"
import { ResultsPanel } from "./results-panel"
import { Header } from "./header"
import { Footer } from "./footer"
import { ScanOptions } from "./scan-options"
import { Navbar } from "./navbar"
import { SettingsPanel } from "./settings-panel"
import { ResponsiveLayout } from "./responsive-layout"
import { useToast } from "@/hooks/use-toast"
import { normalizeUrl } from "@/lib/utils"
import { startScan, getScanResult } from "@/lib/api"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Settings, Target } from "lucide-react"

export type ScanResult = {
  scan_id: string
  domain: string
  url: string
  timestamp: string
  status: string
  modules: Record<string, any>
  error?: string
  use_llm?: boolean
}

export function ReconDashboard() {
  const [url, setUrl] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [currentModule, setCurrentModule] = useState("")
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [selectedModules, setSelectedModules] = useState<string[]>([
    "domain_dns",
    "tech_stack",
    "ports_network",
    "files_directories",
    "api_endpoints",
    "js_analysis",
    "cloud_security",
    "vulnerabilities",
    "email_credentials",
  ])
  const [activeTab, setActiveTab] = useState("scan")
  const [useLLM, setUseLLM] = useState(true)
  const [isAdmin, setIsAdmin] = useState(false) // In a real app, this would be determined by authentication
  const { toast } = useToast()

  const handleScan = async () => {
    if (!url) {
      toast({
        title: "Error",
        description: "Please enter a valid URL",
        variant: "destructive",
      })
      return
    }

    try {
      setIsScanning(true)
      setScanProgress(0)
      setScanResult(null)

      const normalizedUrl = normalizeUrl(url)

      // Start the scan
      const scanResponse = await startScan({
        url: normalizedUrl,
        modules: selectedModules,
        use_llm: useLLM,
      })

      // Set initial scan result
      setScanResult({
        scan_id: scanResponse.scan_id,
        domain: scanResponse.domain,
        url: normalizedUrl,
        timestamp: scanResponse.timestamp,
        status: "scanning",
        modules: {},
        use_llm: scanResponse.use_llm,
      })

      // Poll for scan results
      const pollInterval = setInterval(async () => {
        try {
          const result = await getScanResult(scanResponse.scan_id)
          setScanResult(result)

          // Update progress
          if (result.status === "scanning") {
            // Calculate progress based on completed modules
            const totalModules = selectedModules.length
            const completedModules = Object.keys(result.modules).length
            const progress = Math.floor((completedModules / totalModules) * 100)
            setScanProgress(progress)

            // Set current module (the last one in the list)
            if (completedModules > 0) {
              const lastModule = Object.keys(result.modules)[completedModules - 1]
              setCurrentModule(lastModule)
            }
          } else {
            // Scan is complete or failed
            clearInterval(pollInterval)
            setIsScanning(false)
            setScanProgress(100)
            setCurrentModule("")

            if (result.status === "complete") {
              toast({
                title: "Scan Complete",
                description: `Finished scanning ${normalizedUrl}`,
              })
            } else {
              toast({
                title: "Scan Failed",
                description: result.error || "An error occurred during the scan",
                variant: "destructive",
              })
            }
          }
        } catch (error) {
          console.error("Error polling scan result:", error)
          clearInterval(pollInterval)
          setIsScanning(false)

          toast({
            title: "Error",
            description: "Failed to get scan results",
            variant: "destructive",
          })
        }
      }, 3000) // Poll every 3 seconds
    } catch (error) {
      console.error("Scan error:", error)
      setIsScanning(false)

      toast({
        title: "Scan Failed",
        description: "Failed to start the scan",
        variant: "destructive",
      })
    }
  }

  return (
    <>
      <Navbar scanResult={scanResult} />
      <ResponsiveLayout className="py-8 cyber-bg min-h-screen">
        <div className="cyber-card p-6 rounded-lg mb-8 relative overflow-hidden">
          <div className="scan-line"></div>
          <Header />

          <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-8">
            <TabsList className="grid w-full grid-cols-2 mb-8">
              <TabsTrigger value="scan" className="flex items-center gap-2">
                <Target className="h-4 w-4" />
                <span className="hidden sm:inline">Scan Target</span>
              </TabsTrigger>
              <TabsTrigger value="settings" className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                <span className="hidden sm:inline">Settings</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="scan" className="space-y-8">
              <TargetInput url={url} setUrl={setUrl} onScan={handleScan} isScanning={isScanning} />

              <ScanOptions
                selectedModules={selectedModules}
                setSelectedModules={setSelectedModules}
                disabled={isScanning}
                useLLM={useLLM}
                setUseLLM={setUseLLM}
              />

              {isScanning && <ScanProgress progress={scanProgress} currentModule={currentModule} />}
            </TabsContent>

            <TabsContent value="settings">
              <SettingsPanel isAdmin={isAdmin} />
            </TabsContent>
          </Tabs>
        </div>

        {scanResult && scanResult.status !== "scanning" && (
          <div className="cyber-card p-6 rounded-lg relative overflow-hidden">
            <div className="scan-line"></div>
            <ResultsPanel result={scanResult} />
          </div>
        )}

        <Footer />
      </ResponsiveLayout>
    </>
  )
}
