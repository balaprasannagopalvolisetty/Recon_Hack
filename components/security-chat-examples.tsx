"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { MessageSquare, Shield, AlertTriangle, Lock, Server, Database, Code } from "lucide-react"
import { Badge } from "@/components/ui/badge"

interface SecurityChatExamplesProps {
  onSelectExample: (example: string) => void
}

export function SecurityChatExamples({ onSelectExample }: SecurityChatExamplesProps) {
  const [category, setCategory] = useState<string>("all")

  const examples = [
    {
      id: "xss",
      category: "web",
      title: "Cross-Site Scripting (XSS)",
      description: "What are the risks of XSS vulnerabilities and how can I prevent them?",
      icon: Code,
      severity: "High",
    },
    {
      id: "sql-injection",
      category: "web",
      title: "SQL Injection",
      description: "Explain SQL injection attacks and best practices for prevention",
      icon: Database,
      severity: "Critical",
    },
    {
      id: "csrf",
      category: "web",
      title: "Cross-Site Request Forgery",
      description: "How does CSRF work and what are the best mitigation strategies?",
      icon: AlertTriangle,
      severity: "Medium",
    },
    {
      id: "cloud-misconfig",
      category: "cloud",
      title: "Cloud Misconfigurations",
      description: "What are common cloud security misconfigurations and how to fix them?",
      icon: Server,
      severity: "High",
    },
    {
      id: "api-security",
      category: "api",
      title: "API Security",
      description: "What are the OWASP API security top 10 risks?",
      icon: Code,
      severity: "High",
    },
    {
      id: "ssl-tls",
      category: "network",
      title: "SSL/TLS Issues",
      description: "What are common SSL/TLS misconfigurations and vulnerabilities?",
      icon: Lock,
      severity: "Medium",
    },
    {
      id: "sensitive-data",
      category: "data",
      title: "Sensitive Data Exposure",
      description: "How to identify and prevent sensitive data exposure in web applications?",
      icon: AlertTriangle,
      severity: "High",
    },
    {
      id: "security-headers",
      category: "web",
      title: "Security Headers",
      description: "What security headers should I implement and why?",
      icon: Shield,
      severity: "Medium",
    },
  ]

  const filteredExamples = category === "all" ? examples : examples.filter((example) => example.category === category)

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center">
          <MessageSquare className="mr-2 h-5 w-5 text-blue-400" />
          Security Risk Examples
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Button
              variant={category === "all" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("all")}
              className="text-xs"
            >
              All
            </Button>
            <Button
              variant={category === "web" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("web")}
              className="text-xs"
            >
              Web
            </Button>
            <Button
              variant={category === "cloud" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("cloud")}
              className="text-xs"
            >
              Cloud
            </Button>
            <Button
              variant={category === "api" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("api")}
              className="text-xs"
            >
              API
            </Button>
            <Button
              variant={category === "network" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("network")}
              className="text-xs"
            >
              Network
            </Button>
            <Button
              variant={category === "data" ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory("data")}
              className="text-xs"
            >
              Data
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {filteredExamples.map((example) => (
              <div
                key={example.id}
                className="bg-gray-800 p-3 rounded-lg hover:bg-gray-700 transition-colors cursor-pointer"
                onClick={() => onSelectExample(example.description)}
              >
                <div className="flex items-start space-x-3">
                  <example.icon
                    className={`h-5 w-5 mt-0.5 ${
                      example.severity === "Critical"
                        ? "text-red-500"
                        : example.severity === "High"
                          ? "text-orange-500"
                          : "text-yellow-500"
                    }`}
                  />
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h3 className="font-medium">{example.title}</h3>
                      <Badge
                        variant={
                          example.severity === "Critical"
                            ? "destructive"
                            : example.severity === "High"
                              ? "warning"
                              : "secondary"
                        }
                        className="text-xs"
                      >
                        {example.severity}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{example.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
