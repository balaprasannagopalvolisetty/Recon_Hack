"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { PiIcon as Api, Code } from "lucide-react"

interface ApiEndpointsPanelProps {
  data: any
}

export function ApiEndpointsPanel({ data }: ApiEndpointsPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Api className="mr-2 h-5 w-5" />
            API Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Authentication:</span>
                <span>{data.authentication || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">CORS:</span>
                <Badge
                  variant={
                    data.cors === "permissive" ? "destructive" : data.cors === "misconfigured" ? "warning" : "success"
                  }
                >
                  {data.cors || "Unknown"}
                </Badge>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Swagger/OpenAPI:</span>
                <span>{data.swagger ? "Available" : "Not found"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">GraphQL:</span>
                <span>{data.graphql ? "Available" : "Not found"}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {data.endpoints && data.endpoints.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Api className="mr-2 h-5 w-5" />
              API Endpoints
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                {data.endpoints.map((endpoint: string, i: number) => (
                  <div key={i} className="text-sm font-mono">
                    {endpoint}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.methods && Object.keys(data.methods).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Code className="mr-2 h-5 w-5" />
              HTTP Methods
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Endpoint</th>
                      <th className="text-left py-2 px-4">Methods</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(data.methods).map(([endpoint, methods]: [string, any]) => (
                      <tr key={endpoint} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{endpoint}</td>
                        <td className="py-2 px-4">
                          <div className="flex flex-wrap gap-1">
                            {methods.map((method: string, i: number) => (
                              <Badge
                                key={i}
                                variant={
                                  method === "GET"
                                    ? "info"
                                    : method === "POST"
                                      ? "success"
                                      : method === "DELETE"
                                        ? "destructive"
                                        : "secondary"
                                }
                              >
                                {method}
                              </Badge>
                            ))}
                          </div>
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

      {data.graphql && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Code className="mr-2 h-5 w-5" />
              GraphQL Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Endpoint:</span>
                <span className="font-mono">{data.graphql.endpoint}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Types:</span>
                <span>{data.graphql.types}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Query Type:</span>
                <span>{data.graphql.queryType || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Mutation Type:</span>
                <span>{data.graphql.mutationType || "Unknown"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Subscription Type:</span>
                <span>{data.graphql.subscriptionType || "Unknown"}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
