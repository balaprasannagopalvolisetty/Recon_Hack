"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Textarea } from "@/components/ui/textarea"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/hooks/use-toast"
import { submitFeedback, trainModel } from "@/lib/api"
import type { ScanResult } from "./recon-dashboard"
import { ThumbsUp, ThumbsDown, Loader2, Brain } from "lucide-react"

interface FeedbackPanelProps {
  scanResult: ScanResult
}

export function FeedbackPanel({ scanResult }: FeedbackPanelProps) {
  const [activeTab, setActiveTab] = useState("feedback")
  const [selectedModule, setSelectedModule] = useState("")
  const [selectedFinding, setSelectedFinding] = useState("")
  const [isTruePositive, setIsTruePositive] = useState<boolean | null>(null)
  const [comment, setComment] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isTraining, setIsTraining] = useState(false)
  const { toast } = useToast()

  const handleSubmitFeedback = async () => {
    if (!selectedModule || !selectedFinding || isTruePositive === null) {
      toast({
        title: "Missing Information",
        description: "Please select a module, finding, and indicate if it's a true positive",
        variant: "destructive",
      })
      return
    }

    setIsSubmitting(true)

    try {
      await submitFeedback({
        scan_id: scanResult.scan_id,
        module: selectedModule,
        finding_id: selectedFinding,
        is_true_positive: isTruePositive,
        comment: comment || undefined,
      })

      toast({
        title: "Feedback Submitted",
        description: "Thank you for your feedback!",
      })

      // Reset form
      setSelectedFinding("")
      setIsTruePositive(null)
      setComment("")
    } catch (error) {
      console.error("Error submitting feedback:", error)
      toast({
        title: "Error",
        description: "Failed to submit feedback",
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleTrainModel = async () => {
    setIsTraining(true)

    try {
      const result = await trainModel()

      toast({
        title: "Model Training Initiated",
        description: result.message,
      })
    } catch (error) {
      console.error("Error training model:", error)
      toast({
        title: "Error",
        description: "Failed to train model",
        variant: "destructive",
      })
    } finally {
      setIsTraining(false)
    }
  }

  // Get available modules with findings
  const getModulesWithFindings = () => {
    const modules: { id: string; name: string }[] = []

    if (scanResult.modules.vulnerabilities?.vulnerabilities?.length > 0) {
      modules.push({ id: "vulnerabilities", name: "Vulnerabilities" })
    }
    if (scanResult.modules.cloud_security?.misconfigurations?.length > 0) {
      modules.push({ id: "cloud_security", name: "Cloud Security" })
    }
    if (scanResult.modules.js_analysis?.secrets?.length > 0) {
      modules.push({ id: "js_analysis", name: "JavaScript Analysis" })
    }
    if (scanResult.modules.files_directories?.sensitiveFiles?.length > 0) {
      modules.push({ id: "files_directories", name: "Files & Directories" })
    }

    return modules
  }

  // Get findings for selected module
  const getFindings = () => {
    if (!selectedModule) return []

    switch (selectedModule) {
      case "vulnerabilities":
        return (scanResult.modules.vulnerabilities?.vulnerabilities || []).map((v: any) => ({
          id: v.name,
          name: v.name,
          description: v.description,
          severity: v.severity,
        }))
      case "cloud_security":
        return (scanResult.modules.cloud_security?.misconfigurations || []).map((m: any) => ({
          id: m.type,
          name: m.type,
          description: m.description,
          severity: m.severity,
        }))
      case "js_analysis":
        return (scanResult.modules.js_analysis?.secrets || []).map((s: any) => ({
          id: `${s.type}-${s.file}`,
          name: s.type,
          description: `Found in ${s.file}`,
          severity: "High",
        }))
      case "files_directories":
        return (scanResult.modules.files_directories?.sensitiveFiles || []).map((f: any) => ({
          id: f.file,
          name: f.file,
          description: `Sensitivity level: ${f.level}`,
          severity: f.level === "high" ? "High" : f.level === "medium" ? "Medium" : "Low",
        }))
      default:
        return []
    }
  }

  const modules = getModulesWithFindings()
  const findings = getFindings()

  return (
    <div className="space-y-4">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="feedback">Provide Feedback</TabsTrigger>
          <TabsTrigger value="training">Train Model</TabsTrigger>
        </TabsList>

        <TabsContent value="feedback">
          <Card>
            <CardHeader>
              <CardTitle>Feedback on Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="space-y-2">
                  <Label>Select Module</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {modules.map((module) => (
                      <Button
                        key={module.id}
                        variant={selectedModule === module.id ? "default" : "outline"}
                        onClick={() => {
                          setSelectedModule(module.id)
                          setSelectedFinding("")
                        }}
                        className="justify-start"
                      >
                        {module.name}
                      </Button>
                    ))}
                    {modules.length === 0 && <div className="text-gray-400">No findings available for feedback</div>}
                  </div>
                </div>

                {selectedModule && (
                  <div className="space-y-2">
                    <Label>Select Finding</Label>
                    <div className="grid grid-cols-1 gap-2 max-h-60 overflow-y-auto">
                      {findings.map((finding: any) => (
                        <Button
                          key={finding.id}
                          variant={selectedFinding === finding.id ? "default" : "outline"}
                          onClick={() => setSelectedFinding(finding.id)}
                          className="justify-start text-left h-auto py-3"
                        >
                          <div>
                            <div className="font-medium">{finding.name}</div>
                            <div className="text-xs text-gray-400 mt-1">{finding.description}</div>
                          </div>
                        </Button>
                      ))}
                    </div>
                  </div>
                )}

                {selectedFinding && (
                  <>
                    <div className="space-y-2">
                      <Label>Is this a true positive?</Label>
                      <RadioGroup
                        value={isTruePositive === null ? undefined : isTruePositive.toString()}
                        onValueChange={(value) => setIsTruePositive(value === "true")}
                      >
                        <div className="flex items-center space-x-2">
                          <RadioGroupItem value="true" id="true-positive" />
                          <Label htmlFor="true-positive" className="flex items-center">
                            <ThumbsUp className="h-4 w-4 mr-2 text-green-500" />
                            Yes, this is a real issue
                          </Label>
                        </div>
                        <div className="flex items-center space-x-2">
                          <RadioGroupItem value="false" id="false-positive" />
                          <Label htmlFor="false-positive" className="flex items-center">
                            <ThumbsDown className="h-4 w-4 mr-2 text-red-500" />
                            No, this is a false positive
                          </Label>
                        </div>
                      </RadioGroup>
                    </div>

                    <div className="space-y-2">
                      <Label>Additional Comments (Optional)</Label>
                      <Textarea
                        placeholder="Provide any additional context or information..."
                        value={comment}
                        onChange={(e) => setComment(e.target.value)}
                        rows={4}
                      />
                    </div>

                    <Button onClick={handleSubmitFeedback} disabled={isSubmitting}>
                      {isSubmitting ? (
                        <>
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          Submitting...
                        </>
                      ) : (
                        "Submit Feedback"
                      )}
                    </Button>
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="training">
          <Card>
            <CardHeader>
              <CardTitle>Train AI Model</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="bg-gray-800 p-4 rounded-lg">
                  <p className="text-sm">
                    Training the AI model will use all collected feedback to improve the accuracy of future scans. This
                    process may take some time to complete.
                  </p>
                </div>

                <Button onClick={handleTrainModel} disabled={isTraining} className="w-full">
                  {isTraining ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Training in progress...
                    </>
                  ) : (
                    <>
                      <Brain className="h-4 w-4 mr-2" />
                      Start Training
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
