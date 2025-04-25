"use client"

import { Badge } from "@/components/ui/badge"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { FileText, Upload, Loader2, AlertTriangle, X } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

export function PDFAnalysis() {
  const [file, setFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [results, setResults] = useState<any | null>(null)
  const { toast } = useToast()

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile && selectedFile.type === "application/pdf") {
      setFile(selectedFile)
      setResults(null)
    } else {
      toast({
        title: "Invalid File",
        description: "Please select a valid PDF file",
        variant: "destructive",
      })
    }
  }

  const analyzePDF = async () => {
    if (!file) return

    setIsAnalyzing(true)

    try {
      // In a real implementation, this would upload the file to the backend
      // For now, we'll simulate the analysis
      await new Promise((resolve) => setTimeout(resolve, 3000))

      // Simulated results
      setResults({
        fileName: file.name,
        fileSize: `${(file.size / 1024).toFixed(2)} KB`,
        pages: Math.floor(Math.random() * 20) + 1,
        metadata: {
          author: "Unknown Author",
          creationDate: new Date().toISOString().split("T")[0],
          producer: "PDF Producer",
        },
        securityIssues: [
          {
            type: "Metadata Exposure",
            severity: "Medium",
            description: "Document contains sensitive metadata that could be used for reconnaissance",
          },
          {
            type: "JavaScript Embedded",
            severity: "High",
            description: "PDF contains embedded JavaScript that could potentially execute malicious code",
          },
        ],
        sensitiveData: [
          {
            type: "Email Addresses",
            count: Math.floor(Math.random() * 5) + 1,
          },
          {
            type: "URLs",
            count: Math.floor(Math.random() * 10) + 1,
          },
        ],
      })

      toast({
        title: "Analysis Complete",
        description: "PDF analysis has been completed successfully",
      })
    } catch (error) {
      console.error("Error analyzing PDF:", error)
      toast({
        title: "Analysis Failed",
        description: "Failed to analyze the PDF file",
        variant: "destructive",
      })
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center">
          <FileText className="mr-2 h-5 w-5 text-blue-400" />
          PDF Security Analysis
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {!file ? (
            <div className="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center">
              <div className="flex justify-center mb-4">
                <FileText className="h-12 w-12 text-gray-500" />
              </div>
              <p className="text-gray-400 mb-4">Upload a PDF file for security analysis</p>
              <label className="cursor-pointer">
                <Button variant="outline" className="flex items-center">
                  <Upload className="h-4 w-4 mr-2" />
                  Select PDF
                </Button>
                <input type="file" accept=".pdf" className="hidden" onChange={handleFileChange} />
              </label>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-gray-800 p-3 rounded-lg">
                <div className="flex items-center">
                  <FileText className="h-5 w-5 mr-2 text-blue-400" />
                  <div>
                    <div className="font-medium">{file.name}</div>
                    <div className="text-xs text-gray-400">{(file.size / 1024).toFixed(2)} KB</div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setFile(null)
                      setResults(null)
                    }}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                  <Button onClick={analyzePDF} disabled={isAnalyzing} size="sm">
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <FileText className="h-4 w-4 mr-2" />
                        Analyze
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {results && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-sm text-gray-400 mb-1">Pages</div>
                      <div className="text-xl font-bold">{results.pages}</div>
                    </div>
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-sm text-gray-400 mb-1">Author</div>
                      <div className="text-xl font-bold">{results.metadata.author}</div>
                    </div>
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-sm text-gray-400 mb-1">Creation Date</div>
                      <div className="text-xl font-bold">{results.metadata.creationDate}</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="text-sm font-medium">Security Issues</h3>
                    {results.securityIssues.map((issue: any, i: number) => (
                      <div key={i} className="flex items-start space-x-2 bg-gray-800 p-3 rounded-lg">
                        <AlertTriangle
                          className={`h-5 w-5 mt-0.5 ${issue.severity === "High" ? "text-red-500" : "text-yellow-500"}`}
                        />
                        <div>
                          <div className="font-medium flex items-center">
                            {issue.type}
                            <Badge variant={issue.severity === "High" ? "destructive" : "warning"} className="ml-2">
                              {issue.severity}
                            </Badge>
                          </div>
                          <div className="text-sm text-gray-400">{issue.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="space-y-2">
                    <h3 className="text-sm font-medium">Sensitive Data</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {results.sensitiveData.map((data: any, i: number) => (
                        <div key={i} className="flex justify-between items-center bg-gray-800 p-3 rounded-lg">
                          <span>{data.type}</span>
                          <Badge variant="secondary">{data.count}</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
