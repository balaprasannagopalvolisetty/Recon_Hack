"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Cloud, AlertTriangle } from "lucide-react"

interface CloudSecurityPanelProps {
  data: any
}

export function CloudSecurityPanel({ data }: CloudSecurityPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Cloud className="mr-2 h-5 w-5" />
            Cloud Resources
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">S3 Buckets:</span>
                <span>{data.s3Buckets?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Azure Blobs:</span>
                <span>{data.azureBlobs?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Google Storage:</span>
                <span>{data.googleStorage?.length || 0}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Firebase Apps:</span>
                <span>{data.firebaseApps?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">CloudFront:</span>
                <span>{data.cloudfront?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Publicly Exposed:</span>
                <Badge variant={data.exposed ? "destructive" : "success"}>{data.exposed ? "Yes" : "No"}</Badge>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {data.s3Buckets && data.s3Buckets.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Cloud className="mr-2 h-5 w-5" />
              Amazon S3 Buckets
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">URL</th>
                      <th className="text-left py-2 px-4">Public</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.s3Buckets.map((bucket: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{bucket.url}</td>
                        <td className="py-2 px-4">
                          <Badge variant={bucket.public ? "destructive" : "success"}>
                            {bucket.public ? "Yes" : "No"}
                          </Badge>
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

      {data.misconfigurations && data.misconfigurations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
              Cloud Misconfigurations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Type</th>
                      <th className="text-left py-2 px-4">Service</th>
                      <th className="text-left py-2 px-4">Severity</th>
                      <th className="text-left py-2 px-4">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.misconfigurations.map((misconfig: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{misconfig.type}</td>
                        <td className="py-2 px-4">{misconfig.service}</td>
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

      {data.cloudfront && data.cloudfront.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Cloud className="mr-2 h-5 w-5" />
              CloudFront Distributions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Domain</th>
                      <th className="text-left py-2 px-4">Origin</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.cloudfront.map((distribution: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{distribution.domain}</td>
                        <td className="py-2 px-4 font-mono">{distribution.origin}</td>
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
