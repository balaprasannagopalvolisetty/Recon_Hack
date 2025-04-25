"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, ExternalLink } from "lucide-react"

interface VulnerabilitiesPanelProps {
  data: any
}

export function VulnerabilitiesPanel({ data }: VulnerabilitiesPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="mr-2 h-5 w-5" />
            Security Overview
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Risk Score:</span>
                <Badge
                  variant={
                    data.riskScore === "Critical"
                      ? "destructive"
                      : data.riskScore === "High"
                        ? "destructive"
                        : data.riskScore === "Medium"
                          ? "warning"
                          : "success"
                  }
                >
                  {data.riskScore}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Vulnerabilities:</span>
                <span>{data.vulnerabilities?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">CVEs:</span>
                <span>{data.cves?.length || 0}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Critical:</span>
                <span>{data.vulnerabilities?.filter((v: any) => v.severity === "Critical").length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">High:</span>
                <span>{data.vulnerabilities?.filter((v: any) => v.severity === "High").length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Medium:</span>
                <span>{data.vulnerabilities?.filter((v: any) => v.severity === "Medium").length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Low:</span>
                <span>{data.vulnerabilities?.filter((v: any) => v.severity === "Low").length || 0}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {data.vulnerabilities && data.vulnerabilities.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
              Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Name</th>
                      <th className="text-left py-2 px-4">Severity</th>
                      <th className="text-left py-2 px-4">Description</th>
                      <th className="text-left py-2 px-4">Remediation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.vulnerabilities.map((vuln: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{vuln.name}</td>
                        <td className="py-2 px-4">
                          <Badge
                            variant={
                              vuln.severity === "Critical"
                                ? "destructive"
                                : vuln.severity === "High"
                                  ? "destructive"
                                  : vuln.severity === "Medium"
                                    ? "warning"
                                    : "info"
                            }
                          >
                            {vuln.severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">{vuln.description}</td>
                        <td className="py-2 px-4">{vuln.remediation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.cves && data.cves.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-yellow-500" />
              CVEs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">ID</th>
                      <th className="text-left py-2 px-4">Severity</th>
                      <th className="text-left py-2 px-4">Description</th>
                      <th className="text-left py-2 px-4">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.cves.map((cve: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{cve.id}</td>
                        <td className="py-2 px-4">
                          <Badge
                            variant={
                              cve.severity === "CRITICAL" || cve.severity === "Critical"
                                ? "destructive"
                                : cve.severity === "HIGH" || cve.severity === "High"
                                  ? "destructive"
                                  : cve.severity === "MEDIUM" || cve.severity === "Medium"
                                    ? "warning"
                                    : "info"
                            }
                          >
                            {cve.severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">{cve.description}</td>
                        <td className="py-2 px-4">
                          {cve.url && (
                            <a
                              href={cve.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center text-blue-400 hover:text-blue-300"
                            >
                              <ExternalLink className="h-4 w-4 mr-1" />
                              Details
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.securityIssues && data.securityIssues.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Security Issues
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Issue</th>
                      <th className="text-left py-2 px-4">Severity</th>
                      <th className="text-left py-2 px-4">Status</th>
                      <th className="text-left py-2 px-4">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.securityIssues.map((issue: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{issue.name}</td>
                        <td className="py-2 px-4">
                          <Badge
                            variant={
                              issue.severity === "Critical" || issue.severity === "High"
                                ? "destructive"
                                : issue.severity === "Medium"
                                  ? "warning"
                                  : "info"
                            }
                          >
                            {issue.severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">
                          <Badge variant={issue.status === "Vulnerable" ? "destructive" : "success"}>
                            {issue.status}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">{issue.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {(!data.vulnerabilities || data.vulnerabilities.length === 0) &&
        (!data.cves || data.cves.length === 0) &&
        (!data.securityIssues || data.securityIssues.length === 0) && (
          <Card>
            <CardContent className="py-8">
              <div className="text-center text-gray-400">No vulnerabilities detected</div>
            </CardContent>
          </Card>
        )}

      {data.misconfigurations && data.misconfigurations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-orange-500" />
              Security Misconfigurations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Type</th>
                      <th className="text-left py-2 px-4">Severity</th>
                      <th className="text-left py-2 px-4">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.misconfigurations.map((misconfig: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{misconfig.type}</td>
                        <td className="py-2 px-4">
                          <Badge
                            variant={
                              misconfig.severity === "Critical" || misconfig.severity === "High"
                                ? "destructive"
                                : misconfig.severity === "Medium"
                                  ? "warning"
                                  : "info"
                            }
                          >
                            {misconfig.severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">{misconfig.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
