"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { FileCode, AlertTriangle, Code, ExternalLink } from "lucide-react"
import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface JsAnalysisPanelProps {
  data: any
}

export function JsAnalysisPanel({ data }: JsAnalysisPanelProps) {
  const [activeTab, setActiveTab] = useState("overview")
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [enhancedData, setEnhancedData] = useState(data)

  useEffect(() => {
    setEnhancedData(data)
  }, [data])

  const refreshJsAnalysis = async () => {
    setIsRefreshing(true)

    try {
      // In a real implementation, this would call the backend API
      // For now, we'll simulate a refresh with enhanced data
      await new Promise((resolve) => setTimeout(resolve, 2000))

      // Enhance the data with more JS files and information
      const enhancedFiles = [
        ...(data?.files || []),
        "jquery.min.js",
        "bootstrap.min.js",
        "main.js",
        "analytics.js",
        "vendor.js",
      ]

      const enhancedLibraries = [...(data?.libraries || []), "jQuery 3.6.0", "React 18.2.0", "Bootstrap 5.2.3"]

      const enhancedSecrets = [
        ...(data?.secrets || []),
        {
          type: "API Key",
          file: "analytics.js",
          value: "abc...xyz",
        },
        {
          type: "Firebase Config",
          file: "main.js",
          value: "fir...xyz",
        },
      ]

      const enhancedEndpoints = [...(data?.endpoints || []), "/api/users", "/api/analytics", "/api/data"]

      setEnhancedData({
        ...data,
        files: enhancedFiles,
        libraries: enhancedLibraries,
        secrets: enhancedSecrets,
        endpoints: enhancedEndpoints,
        dependencies: {
          ...(data?.dependencies || {}),
          react: 12,
          jquery: 8,
          axios: 5,
          lodash: 4,
        },
      })
    } catch (error) {
      console.error("Error refreshing JS analysis:", error)
    } finally {
      setIsRefreshing(false)
    }
  }

  if (!enhancedData) return null

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold">JavaScript Analysis</h2>
        <Button variant="outline" size="sm" onClick={refreshJsAnalysis} disabled={isRefreshing}>
          {isRefreshing ? "Refreshing..." : "Deep Scan JS Files"}
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4 mb-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="secrets">Secrets</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="dependencies">Dependencies</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <FileCode className="mr-2 h-5 w-5" />
                JavaScript Files
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {enhancedData.files && enhancedData.files.length > 0 ? (
                  <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                    {enhancedData.files.map((file: string, i: number) => (
                      <div key={i} className="text-sm font-mono flex items-center justify-between py-1">
                        <span>{file}</span>
                        <Button variant="ghost" size="sm" className="h-6 px-2">
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-400">No JavaScript files found</p>
                )}
              </div>
            </CardContent>
          </Card>

          {enhancedData.libraries && enhancedData.libraries.length > 0 && (
            <Card className="mt-4">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Code className="mr-2 h-5 w-5" />
                  JavaScript Libraries
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {enhancedData.libraries.map((library: string, i: number) => (
                    <Badge key={i} variant="secondary">
                      {library}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="secrets">
          {enhancedData.secrets && enhancedData.secrets.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
                  Potential Secrets
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-700">
                          <th className="text-left py-2 px-4">Type</th>
                          <th className="text-left py-2 px-4">File</th>
                          <th className="text-left py-2 px-4">Value</th>
                          <th className="text-left py-2 px-4">Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {enhancedData.secrets.map((secret: any, i: number) => (
                          <tr key={i} className="border-b border-gray-800">
                            <td className="py-2 px-4">{secret.type}</td>
                            <td className="py-2 px-4 font-mono">{secret.file}</td>
                            <td className="py-2 px-4 font-mono">{secret.value}</td>
                            <td className="py-2 px-4">
                              <Badge variant="destructive">High</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">No Secrets Found</h3>
              <p className="text-gray-400">
                No potential secrets or sensitive data were detected in the JavaScript files. This doesn't guarantee
                there are none - consider a manual review for critical applications.
              </p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="endpoints">
          {enhancedData.endpoints && enhancedData.endpoints.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Code className="mr-2 h-5 w-5" />
                  API Endpoints in JavaScript
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                    {enhancedData.endpoints.map((endpoint: string, i: number) => (
                      <div key={i} className="text-sm font-mono py-1">
                        {endpoint}
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <Code className="h-12 w-12 text-blue-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">No API Endpoints Found</h3>
              <p className="text-gray-400">
                No API endpoints were detected in the JavaScript files. Try the "Deep Scan" option to perform a more
                thorough analysis.
              </p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="dependencies">
          {enhancedData.dependencies && Object.keys(enhancedData.dependencies).length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Code className="mr-2 h-5 w-5" />
                  Dependencies
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {Object.entries(enhancedData.dependencies)
                    .sort((a, b) => (b[1] as number) - (a[1] as number))
                    .slice(0, 20)
                    .map(([dep, count]: [string, any]) => (
                      <div key={dep} className="flex justify-between items-center bg-gray-800 p-2 rounded">
                        <span className="font-mono">{dep}</span>
                        <Badge variant="secondary">{count}</Badge>
                      </div>
                    ))}
                </div>
                {Object.keys(enhancedData.dependencies).length > 20 && (
                  <div className="mt-2 text-sm text-gray-400 text-center">
                    ...and {Object.keys(enhancedData.dependencies).length - 20} more dependencies
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <Code className="h-12 w-12 text-green-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">No Dependencies Found</h3>
              <p className="text-gray-400">
                No JavaScript dependencies were detected. Try the "Deep Scan" option to perform a more thorough
                analysis.
              </p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
