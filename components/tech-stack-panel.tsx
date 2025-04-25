"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Code, Server, Database } from "lucide-react"

interface TechStackPanelProps {
  data: any
}

export function TechStackPanel({ data }: TechStackPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Server className="mr-2 h-5 w-5" />
            Server Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Web Server:</span>
                <span>{data.webServer || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">CMS:</span>
                <span>{data.cms || "None detected"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Database:</span>
                <span>{data.database || "None detected"}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Operating System:</span>
                <span>{data.os || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">CDN:</span>
                <span>{data.cdn?.join(", ") || "None detected"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Analytics:</span>
                <span>{data.analytics?.join(", ") || "None detected"}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Code className="mr-2 h-5 w-5" />
            Programming Languages & Frameworks
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {data.languages && data.languages.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2">Languages</h4>
                <div className="flex flex-wrap gap-2">
                  {data.languages.map((lang: string, i: number) => (
                    <Badge key={i} variant="secondary">
                      {lang}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {data.frameworks && data.frameworks.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2">Frameworks</h4>
                <div className="flex flex-wrap gap-2">
                  {data.frameworks.map((framework: string, i: number) => (
                    <Badge key={i} variant="secondary">
                      {framework}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {data.libraries && data.libraries.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2">Libraries</h4>
                <div className="flex flex-wrap gap-2">
                  {data.libraries.map((library: string, i: number) => (
                    <Badge key={i} variant="secondary">
                      {library}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {data.versions && Object.keys(data.versions).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Database className="mr-2 h-5 w-5" />
              Software Versions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(data.versions).map(([software, version]: [string, any]) => (
                <div key={software} className="flex justify-between">
                  <span className="text-gray-400">{software}:</span>
                  <span>{version}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
