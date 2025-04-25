"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Globe, Server, Shield } from "lucide-react"

interface DomainDnsPanelProps {
  data: any
}

export function DomainDnsPanel({ data }: DomainDnsPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Globe className="mr-2 h-5 w-5" />
            Domain Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Domain:</span>
                <span>{data.domain}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">IP Address:</span>
                <span>{data.ip || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Location:</span>
                <span>{data.location || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Hosting:</span>
                <span>{data.hosting || "Unknown"}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Registrar:</span>
                <span>{data.whois?.registrar || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Created:</span>
                <span>{data.whois?.created || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Expires:</span>
                <span>{data.whois?.expires || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Updated:</span>
                <span>{data.whois?.updated || "Unknown"}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Server className="mr-2 h-5 w-5" />
            DNS Records
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {Object.entries(data.dns || {}).map(
              ([recordType, records]: [string, any]) =>
                records &&
                records.length > 0 && (
                  <div key={recordType}>
                    <h4 className="text-sm font-medium mb-2">{recordType.toUpperCase()} Records</h4>
                    <div className="bg-gray-800 p-3 rounded-md">
                      {records.map((record: string, i: number) => (
                        <div key={i} className="text-sm font-mono">
                          {record}
                        </div>
                      ))}
                    </div>
                  </div>
                ),
            )}
          </div>
        </CardContent>
      </Card>

      {data.ssl && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              SSL/TLS Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">SSL Grade:</span>
                  <Badge variant={data.ssl.grade === "A" ? "success" : "warning"}>{data.ssl.grade || "Unknown"}</Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Valid Until:</span>
                  <span>{data.ssl.validUntil || "Unknown"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Issuer:</span>
                  <span>{data.ssl.issuer || "Unknown"}</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-400">Subject:</span>
                  <span>{data.ssl.subject || "Unknown"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Version:</span>
                  <span>{data.ssl.version || "Unknown"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">SANs:</span>
                  <span>{data.ssl.sans?.length || 0} domains</span>
                </div>
              </div>
            </div>

            {data.ssl.sans && data.ssl.sans.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">Subject Alternative Names</h4>
                <div className="bg-gray-800 p-3 rounded-md">
                  {data.ssl.sans.slice(0, 10).map((san: string, i: number) => (
                    <div key={i} className="text-sm font-mono">
                      {san}
                    </div>
                  ))}
                  {data.ssl.sans.length > 10 && (
                    <div className="text-sm font-mono text-gray-400">...and {data.ssl.sans.length - 10} more</div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {data.certificates && data.certificates.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Certificate Transparency
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Issuer</th>
                      <th className="text-left py-2 px-4">Subject</th>
                      <th className="text-left py-2 px-4">Valid From</th>
                      <th className="text-left py-2 px-4">Valid To</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.certificates.map((cert: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{cert.issuer}</td>
                        <td className="py-2 px-4">{cert.subject}</td>
                        <td className="py-2 px-4">{cert.not_before}</td>
                        <td className="py-2 px-4">{cert.not_after}</td>
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
