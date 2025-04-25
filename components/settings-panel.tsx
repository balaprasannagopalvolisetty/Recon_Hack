"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/hooks/use-toast"
import { Loader2, Save, Brain, User, RefreshCw } from "lucide-react"

interface SettingsPanelProps {
  isAdmin: boolean
}

export function SettingsPanel({ isAdmin }: SettingsPanelProps) {
  const [activeTab, setActiveTab] = useState("general")
  const [isLoading, setIsLoading] = useState(false)
  const [enableLLM, setEnableLLM] = useState(true)
  const [defaultModel, setDefaultModel] = useState("ALIENTELLIGENCE/predictivethreatdetection")
  const [availableModels, setAvailableModels] = useState<string[]>([])
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [role, setRole] = useState("user")
  const [verificationCode, setVerificationCode] = useState("")
  const [newModelName, setNewModelName] = useState("")
  const [newModelDescription, setNewModelDescription] = useState("")
  const [baseModel, setBaseModel] = useState("llama3")
  const [systemPrompt, setSystemPrompt] = useState("")
  const { toast } = useToast()

  useEffect(() => {
    // Fetch settings and models if admin
    if (isAdmin) {
      fetchSettings()
      fetchModels()
    }
  }, [isAdmin])

  const fetchSettings = async () => {
    try {
      setIsLoading(true)
      const response = await fetch("/api/settings", {
        headers: {
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setEnableLLM(data.enable_llm)
        setDefaultModel(data.default_llm_model)
      } else {
        toast({
          title: "Error",
          description: "Failed to fetch settings",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error fetching settings:", error)
      toast({
        title: "Error",
        description: "Failed to fetch settings",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const fetchModels = async () => {
    try {
      const response = await fetch("/api/models")

      if (response.ok) {
        const data = await response.json()
        setAvailableModels(data.map((model: any) => model.name))
      }
    } catch (error) {
      console.error("Error fetching models:", error)
    }
  }

  const saveSettings = async () => {
    if (!isAdmin) {
      toast({
        title: "Error",
        description: "You need admin privileges to change settings",
        variant: "destructive",
      })
      return
    }

    try {
      setIsLoading(true)

      const formData = new FormData()
      formData.append("enable_llm", enableLLM.toString())
      formData.append("default_llm_model", defaultModel)

      const response = await fetch("/api/settings", {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
        body: formData,
      })

      if (response.ok) {
        toast({
          title: "Success",
          description: "Settings updated successfully",
        })
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.detail || "Failed to update settings",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error updating settings:", error)
      toast({
        title: "Error",
        description: "Failed to update settings",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const createUser = async () => {
    if (!isAdmin) {
      toast({
        title: "Error",
        description: "You need admin privileges to create users",
        variant: "destructive",
      })
      return
    }

    if (!username || !password) {
      toast({
        title: "Error",
        description: "Username and password are required",
        variant: "destructive",
      })
      return
    }

    try {
      setIsLoading(true)

      const response = await fetch("/api/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
        body: JSON.stringify({
          username,
          password,
          role,
        }),
      })

      if (response.ok) {
        toast({
          title: "Success",
          description: "User created successfully",
        })
        setUsername("")
        setPassword("")
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.detail || "Failed to create user",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error creating user:", error)
      toast({
        title: "Error",
        description: "Failed to create user",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const getVerificationCode = async () => {
    try {
      setIsLoading(true)

      const response = await fetch("/api/verification-code", {
        headers: {
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setVerificationCode(data.code)
        toast({
          title: "Verification Code",
          description: `Your code is: ${data.code} (expires in ${data.expires_in})`,
        })
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.detail || "Failed to get verification code",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error getting verification code:", error)
      toast({
        title: "Error",
        description: "Failed to get verification code",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const trainModel = async () => {
    if (!isAdmin) {
      toast({
        title: "Error",
        description: "You need admin privileges to train models",
        variant: "destructive",
      })
      return
    }

    if (!newModelName || !verificationCode) {
      toast({
        title: "Error",
        description: "Model name and verification code are required",
        variant: "destructive",
      })
      return
    }

    try {
      setIsLoading(true)

      const response = await fetch("/api/train", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
        body: JSON.stringify({
          name: newModelName,
          description: newModelDescription || `Custom model based on ${baseModel}`,
          base_model: baseModel,
          system_prompt: systemPrompt,
          verification_code: verificationCode,
        }),
      })

      if (response.ok) {
        const data = await response.json()
        toast({
          title: "Success",
          description: data.message,
        })
        setNewModelName("")
        setNewModelDescription("")
        setVerificationCode("")
        // Refresh models list
        fetchModels()
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.detail || "Failed to train model",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error training model:", error)
      toast({
        title: "Error",
        description: "Failed to train model",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="general">General Settings</TabsTrigger>
          {isAdmin && <TabsTrigger value="users">User Management</TabsTrigger>}
          {isAdmin && <TabsTrigger value="models">Model Training</TabsTrigger>}
        </TabsList>

        <TabsContent value="general">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label htmlFor="enable-llm">Enable AI Analysis</Label>
                    <p className="text-sm text-gray-400">
                      When enabled, the system will use LLMs for analysis. When disabled, AI analysis will not be
                      available.
                    </p>
                  </div>
                  <Switch
                    id="enable-llm"
                    checked={enableLLM}
                    onCheckedChange={setEnableLLM}
                    disabled={!isAdmin || isLoading}
                  />
                </div>

                {isAdmin && (
                  <div className="space-y-2">
                    <Label htmlFor="default-model">Default LLM Model</Label>
                    <div className="flex space-x-2">
                      <Input
                        id="default-model"
                        value={defaultModel}
                        onChange={(e) => setDefaultModel(e.target.value)}
                        disabled={isLoading}
                        className="flex-grow"
                      />
                      <Button onClick={saveSettings} disabled={isLoading}>
                        {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                      </Button>
                    </div>
                    <p className="text-xs text-gray-400">Available models: {availableModels.join(", ")}</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {isAdmin && (
          <TabsContent value="users">
            <Card>
              <CardHeader>
                <CardTitle>User Management</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="username">Username</Label>
                    <Input
                      id="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      disabled={isLoading}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={isLoading}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="role">Role</Label>
                    <select
                      id="role"
                      value={role}
                      onChange={(e) => setRole(e.target.value)}
                      disabled={isLoading}
                      className="w-full p-2 rounded-md border border-gray-300 bg-background"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>

                  <Button onClick={createUser} disabled={isLoading} className="w-full">
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Creating...
                      </>
                    ) : (
                      <>
                        <User className="h-4 w-4 mr-2" />
                        Create User
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {isAdmin && (
          <TabsContent value="models">
            <Card>
              <CardHeader>
                <CardTitle>Model Training</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="new-model-name">Model Name</Label>
                    <Input
                      id="new-model-name"
                      value={newModelName}
                      onChange={(e) => setNewModelName(e.target.value)}
                      disabled={isLoading}
                      placeholder="e.g., my-custom-model"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="new-model-description">Description</Label>
                    <Input
                      id="new-model-description"
                      value={newModelDescription}
                      onChange={(e) => setNewModelDescription(e.target.value)}
                      disabled={isLoading}
                      placeholder="Custom security model"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="base-model">Base Model</Label>
                    <select
                      id="base-model"
                      value={baseModel}
                      onChange={(e) => setBaseModel(e.target.value)}
                      disabled={isLoading}
                      className="w-full p-2 rounded-md border border-gray-300 bg-background"
                    >
                      <option value="llama3">Llama 3</option>
                      <option value="mistral">Mistral</option>
                      <option value="gemma">Gemma</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="system-prompt">System Prompt (Optional)</Label>
                    <textarea
                      id="system-prompt"
                      value={systemPrompt}
                      onChange={(e) => setSystemPrompt(e.target.value)}
                      disabled={isLoading}
                      className="w-full p-2 rounded-md border border-gray-300 bg-background h-24"
                      placeholder="You are an advanced cybersecurity AI assistant..."
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <Label htmlFor="verification-code">Verification Code</Label>
                      <Button variant="outline" size="sm" onClick={getVerificationCode} disabled={isLoading}>
                        <RefreshCw className="h-4 w-4 mr-1" />
                        Get Code
                      </Button>
                    </div>
                    <Input
                      id="verification-code"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value)}
                      disabled={isLoading}
                      placeholder="Enter verification code"
                    />
                    <p className="text-xs text-gray-400">A verification code is required for security purposes.</p>
                  </div>

                  <Button onClick={trainModel} disabled={isLoading} className="w-full">
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Training...
                      </>
                    ) : (
                      <>
                        <Brain className="h-4 w-4 mr-2" />
                        Train Model
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}
