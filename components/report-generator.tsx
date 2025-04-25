"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { useToast } from "@/hooks/use-toast"
import { FileText, Download, Loader2 } from "lucide-react"
import { API_BASE_URL } from "@/lib/api"

interface ReportGeneratorProps {
  scanResult: any
}

export function ReportGenerator({ scanResult }: ReportGeneratorProps) {
  const [isGenerating, setIsGenerating] = useState(false)
  const [reportFilename, setReportFilename] = useState<string | null>(null)
  const [selectedModules, setSelectedModules] = useState<string[]>([])
  const { toast } = useToast()

  const availableModules = Object.keys(scanResult.modules || {})

  const toggleModule = (module: string) => {
    if (selectedModules.includes(module)) {
      setSelectedModules(selectedModules.filter((m) => m !== module))
    } else {
      setSelectedModules([...selectedModules, module])
    }
  }

  const selectAllModules = () => {
    setSelectedModules([...availableModules])
  }

  const clearAllModules = () => {
    setSelectedModules([])
  }

  const generateReport = async () => {
    if (!scanResult.scan_id) {
      toast({
        title: "Error",
        description: "No scan result available to generate report",
        variant: "destructive",
      })
      return
    }

    try {
      setIsGenerating(true)

      const modulesParam = selectedModules.length > 0 ? `?include_modules=${selectedModules.join(",")}` : ""

      const response = await fetch(`${API_BASE_URL}/api/report/${scanResult.scan_id}${modulesParam}`)

      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${await response.text()}`)
      }

      const data = await response.json()

      // Store the filename for download
      setReportFilename(data.filename)

      toast({
        title: "Success",
        description: "PDF report generated successfully",
      })
    } catch (error) {
      console.error("Error generating report:", error)
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to generate report",
        variant: "destructive",
      })
    } finally {
      setIsGenerating(false)
    }
  }

  const downloadReport = () => {
    if (reportFilename) {
      // Use the direct download endpoint
      window.open(`${API_BASE_URL}/download/report/${reportFilename}`, "_blank")
    }
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center">
          <FileText className="mr-2 h-5 w-5 text-blue-400" />
          Generate PDF Report
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <div className="bg-gray-800/50 p-4 rounded-md">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-sm font-medium">Select Modules to Include</h3>
              <div className="space-x-2">
                <Button variant="outline" size="sm" onClick={selectAllModules}>
                  Select All
                </Button>
                <Button variant="outline" size="sm" onClick={clearAllModules}>
                  Clear All
                </Button>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {availableModules.map((module) => (
                <div key={module} className="flex items-center space-x-2">
                  <Checkbox
                    id={`module-${module}`}
                    checked={selectedModules.includes(module)}
                    onCheckedChange={() => toggleModule(module)}
                  />
                  <Label htmlFor={`module-${module}`} className="text-sm font-medium cursor-pointer">
                    {module.replace("_", " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                  </Label>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col md:flex-row gap-4">
            <Button onClick={generateReport} disabled={isGenerating} className="flex-1">
              {isGenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Generating Report...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4 mr-2" />
                  Generate PDF Report
                </>
              )}
            </Button>

            {reportFilename && (
              <Button onClick={downloadReport} variant="outline" className="flex-1">
                <Download className="h-4 w-4 mr-2" />
                Download Report
              </Button>
            )}
          </div>

          {reportFilename && (
            <div className="bg-green-900/20 border border-green-500/30 p-4 rounded-md text-center">
              <FileText className="h-8 w-8 mx-auto mb-2 text-green-500" />
              <h3 className="text-lg font-medium mb-2 text-green-400">Report Generated Successfully</h3>
              <p className="text-sm text-green-300 mb-4">Your comprehensive security report is ready for download</p>
              <Button variant="outline" onClick={downloadReport} className="border-green-500">
                <Download className="h-4 w-4 mr-2" />
                Download Report
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
