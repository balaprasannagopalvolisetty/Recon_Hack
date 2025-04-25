"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Mail, AlertTriangle, ExternalLink } from "lucide-react"

interface EmailCredentialsPanelProps {
  data: any
}

export function EmailCredentialsPanel({ data }: EmailCredentialsPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      {data.emails && data.emails.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Mail className="mr-2 h-5 w-5" />
              Email Addresses
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                {data.emails.map((email: string, i: number) => (
                  <div key={i} className="text-sm font-mono">
                    {email}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.pastBreaches && data.pastBreaches.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
              Past Breaches
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Breach</th>
                      <th className="text-left py-2 px-4">Date</th>
                      <th className="text-left py-2 px-4">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.pastBreaches.map((breach: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{breach.name}</td>
                        <td className="py-2 px-4">{breach.date}</td>
                        <td className="py-2 px-4">{breach.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.exposedData && Object.keys(data.exposedData).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-yellow-500" />
              Exposed Data Types
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(data.exposedData).map(([dataType, count]: [string, any]) => (
                <div key={dataType} className="flex justify-between items-center bg-gray-800 p-2 rounded">
                  <span>{dataType}</span>
                  <Badge variant="secondary">{count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {data.articles && data.articles.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <ExternalLink className="mr-2 h-5 w-5" />
              Related Articles
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {data.articles.map((article: any, i: number) => (
                <div key={i} className="bg-gray-800 p-3 rounded-md">
                  <a
                    href={article.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center text-blue-400 hover:text-blue-300"
                  >
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {article.title}
                  </a>
                  <div className="text-sm text-gray-400 mt-1">{article.date}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {data.credentials && data.credentials.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
              Leaked Credentials
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Username/Email</th>
                      <th className="text-left py-2 px-4">Source</th>
                      <th className="text-left py-2 px-4">Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.credentials.map((cred: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{cred.username}</td>
                        <td className="py-2 px-4">{cred.source}</td>
                        <td className="py-2 px-4">{cred.date}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {(!data.emails || data.emails.length === 0) &&
        (!data.pastBreaches || data.pastBreaches.length === 0) &&
        (!data.exposedData || Object.keys(data.exposedData).length === 0) &&
        (!data.articles || data.articles.length === 0) &&
        (!data.credentials || data.credentials.length === 0) && (
          <Card>
            <CardContent className="py-8">
              <div className="text-center text-gray-400">No email or credential information found</div>
            </CardContent>
          </Card>
        )}
    </div>
  )
}
