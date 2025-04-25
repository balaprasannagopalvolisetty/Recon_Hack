"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Folder, File, AlertTriangle } from "lucide-react"

interface FilesDirectoriesPanelProps {
  data: any
}

export function FilesDirectoriesPanel({ data }: FilesDirectoriesPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Folder className="mr-2 h-5 w-5" />
            Directories
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {data.directories && data.directories.length > 0 ? (
              <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                {data.directories.map((dir: string, i: number) => (
                  <div key={i} className="text-sm font-mono">
                    {dir}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-400">No directories found</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <File className="mr-2 h-5 w-5" />
            Files
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {data.files && data.files.length > 0 ? (
              <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                {data.files.map((file: string, i: number) => (
                  <div key={i} className="text-sm font-mono">
                    {file}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-400">No files found</p>
            )}
          </div>
        </CardContent>
      </Card>

      {data.sensitiveFiles && data.sensitiveFiles.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-yellow-500" />
              Sensitive Files
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">File</th>
                      <th className="text-left py-2 px-4">Sensitivity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sensitiveFiles.map((file: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4 font-mono">{file.file}</td>
                        <td className="py-2 px-4">
                          <Badge
                            variant={
                              file.level === "high" ? "destructive" : file.level === "medium" ? "warning" : "info"
                            }
                          >
                            {file.level}
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

      {data.backups && data.backups.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-500" />
              Backup Files
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-gray-800 p-3 rounded-md max-h-60 overflow-y-auto">
                {data.backups.map((backup: string, i: number) => (
                  <div key={i} className="text-sm font-mono">
                    {backup}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data.extensions && Object.keys(data.extensions).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <File className="mr-2 h-5 w-5" />
              File Extensions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(data.extensions).map(([ext, count]: [string, any]) => (
                <div key={ext} className="flex justify-between items-center bg-gray-800 p-2 rounded">
                  <span className="font-mono">{ext}</span>
                  <Badge variant="secondary">{count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
