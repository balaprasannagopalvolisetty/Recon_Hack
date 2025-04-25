"use client"

import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ChatPanel } from "./chat-panel"
import { FeedbackPanel } from "./feedback-panel"
import { DomainDnsPanel } from "./domain-dns-panel"
import { TechStackPanel } from "./tech-stack-panel"
import { PortsNetworkPanel } from "./ports-network-panel"
import { FilesDirectoriesPanel } from "./files-directories-panel"
import { ApiEndpointsPanel } from "./api-endpoints-panel"
import { JsAnalysisPanel } from "./js-analysis-panel"
import { CloudSecurityPanel } from "./cloud-security-panel"
import { VulnerabilitiesPanel } from "./vulnerabilities-panel"
import { EmailCredentialsPanel } from "./email-credentials-panel"
import { AccuracyMetrics } from "./accuracy-metrics"
import { PDFAnalysis } from "./pdf-analysis"
import { ResponsiveLayout } from "./responsive-layout"
import type { ScanResult } from "./recon-dashboard"
import { ReportGenerator } from "./report-generator"
import {
  Globe,
  Code,
  Network,
  Folder,
  PiIcon as Api,
  FileCode,
  Cloud,
  Shield,
  Mail,
  MessageSquare,
  ThumbsUp,
  BarChart3,
  FileText,
} from "lucide-react"

interface ResultsPanelProps {
  result: ScanResult
}

export function ResultsPanel({ result }: ResultsPanelProps) {
  const [activeTab, setActiveTab] = useState("overview")

  // Count findings by severity
  const countFindings = () => {
    let critical = 0
    let high = 0
    let medium = 0
    let low = 0

    // Count vulnerabilities
    if (result.modules.vulnerabilities) {
      const vulns = result.modules.vulnerabilities.vulnerabilities || []
      critical += vulns.filter((v: any) => v.severity === "Critical").length
      high += vulns.filter((v: any) => v.severity === "High").length
      medium += vulns.filter((v: any) => v.severity === "Medium").length
      low += vulns.filter((v: any) => v.severity === "Low").length
    }

    // Count cloud misconfigurations
    if (result.modules.cloud_security) {
      const misconfigs = result.modules.cloud_security.misconfigurations || []
      critical += misconfigs.filter((m: any) => m.severity === "Critical").length
      high += misconfigs.filter((m: any) => m.severity === "High").length
      medium += misconfigs.filter((m: any) => m.severity === "Medium").length
      low += misconfigs.filter((m: any) => m.severity === "Low").length
    }

    // Count sensitive files
    if (result.modules.files_directories) {
      const sensitiveFiles = result.modules.files_directories.sensitiveFiles || []
      high += sensitiveFiles.filter((f: any) => f.level === "high").length
      medium += sensitiveFiles.filter((f: any) => f.level === "medium").length
      low += sensitiveFiles.filter((f: any) => f.level === "low").length
    }

    // Count JS secrets
    if (result.modules.js_analysis) {
      const secrets = result.modules.js_analysis.secrets || []
      high += secrets.length
    }

    return { critical, high, medium, low }
  }

  const findings = countFindings()
  const totalFindings = findings.critical + findings.high + findings.medium + findings.low

  return (
    <ResponsiveLayout className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Scan Results: {result.domain}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-gray-800 p-4 rounded-lg">
              <div className="text-sm text-gray-400">Critical Findings</div>
              <div className="text-2xl font-bold mt-1 flex items-center">
                {findings.critical}
                {findings.critical > 0 && (
                  <Badge variant="destructive" className="ml-2">
                    Critical
                  </Badge>
                )}
              </div>
            </div>
            <div className="bg-gray-800 p-4 rounded-lg">
              <div className="text-sm text-gray-400">High Findings</div>
              <div className="text-2xl font-bold mt-1 flex items-center">
                {findings.high}
                {findings.high > 0 && (
                  <Badge variant="destructive" className="ml-2">
                    High
                  </Badge>
                )}
              </div>
            </div>
            <div className="bg-gray-800 p-4 rounded-lg">
              <div className="text-sm text-gray-400">Medium Findings</div>
              <div className="text-2xl font-bold mt-1 flex items-center">
                {findings.medium}
                {findings.medium > 0 && (
                  <Badge variant="warning" className="ml-2">
                    Medium
                  </Badge>
                )}
              </div>
            </div>
            <div className="bg-gray-800 p-4 rounded-lg">
              <div className="text-sm text-gray-400">Low Findings</div>
              <div className="text-2xl font-bold mt-1 flex items-center">
                {findings.low}
                {findings.low > 0 && (
                  <Badge variant="info" className="ml-2">
                    Low
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="flex flex-wrap w-full">
          <TabsTrigger value="overview" className="flex items-center gap-1">
            <Shield className="h-4 w-4" />
            <span className="hidden md:inline">Overview</span>
          </TabsTrigger>
          {result.modules.domain_dns && (
            <TabsTrigger value="domain_dns" className="flex items-center gap-1">
              <Globe className="h-4 w-4" />
              <span className="hidden md:inline">Domain</span>
            </TabsTrigger>
          )}
          {result.modules.tech_stack && (
            <TabsTrigger value="tech_stack" className="flex items-center gap-1">
              <Code className="h-4 w-4" />
              <span className="hidden md:inline">Tech</span>
            </TabsTrigger>
          )}
          {result.modules.ports_network && (
            <TabsTrigger value="ports_network" className="flex items-center gap-1">
              <Network className="h-4 w-4" />
              <span className="hidden md:inline">Ports</span>
            </TabsTrigger>
          )}
          {result.modules.files_directories && (
            <TabsTrigger value="files_directories" className="flex items-center gap-1">
              <Folder className="h-4 w-4" />
              <span className="hidden md:inline">Files</span>
            </TabsTrigger>
          )}
          {result.modules.api_endpoints && (
            <TabsTrigger value="api_endpoints" className="flex items-center gap-1">
              <Api className="h-4 w-4" />
              <span className="hidden md:inline">API</span>
            </TabsTrigger>
          )}
          {result.modules.js_analysis && (
            <TabsTrigger value="js_analysis" className="flex items-center gap-1">
              <FileCode className="h-4 w-4" />
              <span className="hidden md:inline">JS</span>
            </TabsTrigger>
          )}
          {result.modules.cloud_security && (
            <TabsTrigger value="cloud_security" className="flex items-center gap-1">
              <Cloud className="h-4 w-4" />
              <span className="hidden md:inline">Cloud</span>
            </TabsTrigger>
          )}
          {result.modules.vulnerabilities && (
            <TabsTrigger value="vulnerabilities" className="flex items-center gap-1">
              <Shield className="h-4 w-4" />
              <span className="hidden md:inline">Vulns</span>
            </TabsTrigger>
          )}
          {result.modules.email_credentials && (
            <TabsTrigger value="email_credentials" className="flex items-center gap-1">
              <Mail className="h-4 w-4" />
              <span className="hidden md:inline">Email</span>
            </TabsTrigger>
          )}
          <TabsTrigger value="ai_analysis" className="flex items-center gap-1">
            <MessageSquare className="h-4 w-4" />
            <span className="hidden md:inline">AI</span>
          </TabsTrigger>
          <TabsTrigger value="metrics" className="flex items-center gap-1">
            <BarChart3 className="h-4 w-4" />
            <span className="hidden md:inline">Metrics</span>
          </TabsTrigger>
          <TabsTrigger value="pdf_analysis" className="flex items-center gap-1">
            <FileText className="h-4 w-4" />
            <span className="hidden md:inline">PDF</span>
          </TabsTrigger>
          <TabsTrigger value="feedback" className="flex items-center gap-1">
            <ThumbsUp className="h-4 w-4" />
            <span className="hidden md:inline">Feedback</span>
          </TabsTrigger>
          <TabsTrigger value="report" className="flex items-center gap-1">
            <FileText className="h-4 w-4" />
            <span className="hidden md:inline">Report</span>
          </TabsTrigger>
        </TabsList>

        <div className="mt-4">
          <TabsContent value="overview">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Scan Summary</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Target:</span>
                      <span>{result.domain}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Scan ID:</span>
                      <span className="font-mono text-xs">{result.scan_id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Timestamp:</span>
                      <span>{new Date(result.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Status:</span>
                      <Badge variant={result.status === "complete" ? "success" : "destructive"}>{result.status}</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Modules:</span>
                      <span>{Object.keys(result.modules).length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Total Findings:</span>
                      <span>{totalFindings}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">AI Analysis:</span>
                      <Badge variant={result.use_llm ? "success" : "secondary"}>
                        {result.use_llm ? "Enabled" : "Disabled"}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="h-full">
                <CardHeader>
                  <CardTitle>Risk Overview</CardTitle>
                </CardHeader>
                <CardContent>
                  {result.modules.vulnerabilities?.riskScore && (
                    <div className="mb-4">
                      <div className="text-sm text-gray-400 mb-1">Overall Risk Score</div>
                      <div className="flex items-center">
                        <Badge
                          variant={
                            result.modules.vulnerabilities.riskScore === "Critical" ||
                            result.modules.vulnerabilities.riskScore === "High"
                              ? "destructive"
                              : result.modules.vulnerabilities.riskScore === "Medium"
                                ? "warning"
                                : "success"
                          }
                          className="text-lg py-1 px-3"
                        >
                          {result.modules.vulnerabilities.riskScore}
                        </Badge>
                      </div>
                    </div>
                  )}

                  <div className="space-y-2">
                    {findings.critical > 0 && (
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Critical Issues:</span>
                        <Badge variant="destructive">{findings.critical}</Badge>
                      </div>
                    )}
                    {findings.high > 0 && (
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">High Issues:</span>
                        <Badge variant="destructive">{findings.high}</Badge>
                      </div>
                    )}
                    {findings.medium > 0 && (
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Medium Issues:</span>
                        <Badge variant="warning">{findings.medium}</Badge>
                      </div>
                    )}
                    {findings.low > 0 && (
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Low Issues:</span>
                        <Badge variant="info">{findings.low}</Badge>
                      </div>
                    )}
                    {totalFindings === 0 && <div className="text-center text-gray-400 py-4">No issues detected</div>}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="domain_dns">
            <DomainDnsPanel data={result.modules.domain_dns} />
          </TabsContent>

          <TabsContent value="tech_stack">
            <TechStackPanel data={result.modules.tech_stack} />
          </TabsContent>

          <TabsContent value="ports_network">
            <PortsNetworkPanel data={result.modules.ports_network} />
          </TabsContent>

          <TabsContent value="files_directories">
            <FilesDirectoriesPanel data={result.modules.files_directories} />
          </TabsContent>

          <TabsContent value="api_endpoints">
            <ApiEndpointsPanel data={result.modules.api_endpoints} />
          </TabsContent>

          <TabsContent value="js_analysis">
            <JsAnalysisPanel data={result.modules.js_analysis} />
          </TabsContent>

          <TabsContent value="cloud_security">
            <CloudSecurityPanel data={result.modules.cloud_security} />
          </TabsContent>

          <TabsContent value="vulnerabilities">
            <VulnerabilitiesPanel data={result.modules.vulnerabilities} />
          </TabsContent>

          <TabsContent value="email_credentials">
            <EmailCredentialsPanel data={result.modules.email_credentials} />
          </TabsContent>

          <TabsContent value="ai_analysis">
            <div className="h-[600px]">
              <ChatPanel scanResult={result} />
            </div>
          </TabsContent>

          <TabsContent value="metrics">
            <AccuracyMetrics scanResult={result} />
          </TabsContent>

          <TabsContent value="pdf_analysis">
            <PDFAnalysis />
          </TabsContent>

          <TabsContent value="feedback">
            <FeedbackPanel scanResult={result} />
          </TabsContent>
          <TabsContent value="report">
            <ReportGenerator scanResult={result} />
          </TabsContent>
        </div>
      </Tabs>
    </ResponsiveLayout>
  )
}
