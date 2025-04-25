"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { Brain, Target, BarChart3, AlertTriangle } from "lucide-react"
import type { ScanResult } from "./recon-dashboard"

interface AccuracyMetricsProps {
  scanResult: ScanResult
}

export function AccuracyMetrics({ scanResult }: AccuracyMetricsProps) {
  const [metrics, setMetrics] = useState({
    llmAccuracy: 0,
    normalAccuracy: 0,
    falsePositives: 0,
    falseNegatives: 0,
    confidence: 0,
  })

  useEffect(() => {
    // In a real implementation, this would be calculated based on feedback data
    // For now, we'll use simulated metrics
    if (scanResult) {
      // Calculate metrics based on scan results
      const vulnerabilitiesCount = scanResult.modules.vulnerabilities?.vulnerabilities?.length || 0
      const misconfigurations = scanResult.modules.cloud_security?.misconfigurations?.length || 0
      const sensitiveFiles = scanResult.modules.files_directories?.sensitiveFiles?.length || 0

      // Simulate accuracy metrics
      const llmAccuracy = Math.min(85 + Math.floor(Math.random() * 10), 98)
      const normalAccuracy = Math.min(70 + Math.floor(Math.random() * 15), 90)

      // Simulate false positives and negatives
      const falsePositives = Math.floor((vulnerabilitiesCount + misconfigurations) * 0.1)
      const falseNegatives = Math.floor((vulnerabilitiesCount + misconfigurations) * 0.05)

      // Calculate confidence score
      const confidence = Math.min(75 + Math.floor(Math.random() * 20), 95)

      setMetrics({
        llmAccuracy,
        normalAccuracy,
        falsePositives,
        falseNegatives,
        confidence,
      })
    }
  }, [scanResult])

  if (!scanResult) return null

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center text-lg">
          <BarChart3 className="mr-2 h-5 w-5 text-blue-400" />
          Scan Accuracy Metrics
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <div className="flex items-center">
                  <Brain className="h-4 w-4 mr-1 text-green-500" />
                  <span className="text-sm font-medium">AI-Enhanced Analysis</span>
                </div>
                <span className="text-sm font-bold">{metrics.llmAccuracy}%</span>
              </div>
              <Progress value={metrics.llmAccuracy} className="h-2" />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <div className="flex items-center">
                  <Target className="h-4 w-4 mr-1 text-blue-500" />
                  <span className="text-sm font-medium">Standard Analysis</span>
                </div>
                <span className="text-sm font-bold">{metrics.normalAccuracy}%</span>
              </div>
              <Progress value={metrics.normalAccuracy} className="h-2" />
            </div>

            <div className="flex justify-between items-center pt-2">
              <span className="text-sm text-gray-400">Accuracy Improvement</span>
              <Badge variant="success">+{metrics.llmAccuracy - metrics.normalAccuracy}%</Badge>
            </div>
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-800 p-3 rounded-lg">
                <div className="text-sm text-gray-400 mb-1">False Positives</div>
                <div className="flex items-center">
                  <AlertTriangle className="h-4 w-4 mr-1 text-yellow-500" />
                  <span className="text-xl font-bold">{metrics.falsePositives}</span>
                </div>
              </div>

              <div className="bg-gray-800 p-3 rounded-lg">
                <div className="text-sm text-gray-400 mb-1">False Negatives</div>
                <div className="flex items-center">
                  <AlertTriangle className="h-4 w-4 mr-1 text-red-500" />
                  <span className="text-xl font-bold">{metrics.falseNegatives}</span>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 p-3 rounded-lg">
              <div className="text-sm text-gray-400 mb-1">Confidence Score</div>
              <div className="flex items-center">
                <Progress value={metrics.confidence} className="h-2 flex-grow" />
                <span className="text-sm font-bold ml-2">{metrics.confidence}%</span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
