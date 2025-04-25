"use client"

import { useState, useRef, useEffect } from "react"
import { Send, Loader2, Terminal, X, Bot, AlertTriangle, ToggleLeft, ToggleRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useToast } from "@/hooks/use-toast"
import { SecurityChatExamples } from "./security-chat-examples"
import type { ScanResult } from "./recon-dashboard"

interface Message {
  role: "user" | "assistant" | "system"
  content: string
}

interface ChatInterfaceProps {
  onClose: () => void
  scanResult?: ScanResult | null
}

export function ChatInterface({ onClose, scanResult }: ChatInterfaceProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "system",
      content: "ALIENTELLIGENCE/predictivethreatdetection initialized. How can I assist with your security analysis?",
    },
  ])
  const [input, setInput] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [isInitializing, setIsInitializing] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [useLLM, setUseLLM] = useState(true)
  const [showExamples, setShowExamples] = useState(true)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const { toast } = useToast()

  // Simulate initialization
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsInitializing(false)

      // If we have scan results, add a system message about it
      if (scanResult) {
        setMessages((prev) => [
          ...prev,
          {
            role: "system",
            content: `Scan data loaded for ${scanResult.domain}. You can ask specific questions about the scan results.`,
          },
        ])

        // Check if LLM is enabled for this scan
        if (scanResult.use_llm === false) {
          setUseLLM(false)
          setMessages((prev) => [
            ...prev,
            {
              role: "system",
              content: "Note: AI analysis is currently disabled. Enable it in settings to use AI-powered responses.",
            },
          ])
        }
      }
    }, 2000)
    return () => clearTimeout(timer)
  }, [scanResult])

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  const handleSendMessage = async () => {
    if (!input.trim() || isLoading) return

    // Add user message
    const userMessage: Message = {
      role: "user",
      content: input,
    }
    setMessages((prev) => [...prev, userMessage])
    setInput("")
    setIsLoading(true)
    setError(null)
    setShowExamples(false)

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: input,
          scanData: scanResult,
          use_llm: useLLM,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Failed to get response")
      }

      const data = await response.json()

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.response,
        },
      ])
    } catch (err) {
      console.error("Error sending message:", err)
      setError(err instanceof Error ? err.message : "Failed to communicate with AI model")
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : "Failed to communicate with AI model",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const toggleLLM = () => {
    setUseLLM(!useLLM)
    setMessages((prev) => [
      ...prev,
      {
        role: "system",
        content: !useLLM
          ? "AI analysis enabled. Responses will now use the LLM model."
          : "AI analysis disabled. Responses will not use the LLM model.",
      },
    ])
  }

  const handleExampleSelect = (example: string) => {
    setInput(example)
    setShowExamples(false)
  }

  return (
    <div className="flex flex-col h-full terminal">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-green-500/30">
        <div className="flex items-center">
          <Terminal className="h-5 w-5 text-green-500 mr-2" />
          <h3 className="text-green-500 font-bold terminal-text">ALIENTELLIGENCE/predictivethreatdetection</h3>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleLLM}
            className="text-green-500 hover:text-green-400"
            title={useLLM ? "Disable AI" : "Enable AI"}
          >
            {useLLM ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
          </Button>
          <Button variant="ghost" size="icon" onClick={onClose} className="text-green-500 hover:text-green-400">
            <X className="h-5 w-5" />
          </Button>
        </div>
      </div>

      {/* Initialization screen */}
      {isInitializing ? (
        <div className="flex-1 flex flex-col items-center justify-center p-4">
          <Bot className="h-16 w-16 text-green-500 mb-4 animate-pulse" />
          <div className="text-green-500 text-center mb-4 cyber-glow">Initializing AI Model</div>
          <div className="w-48 h-2 bg-green-900/30 rounded-full overflow-hidden">
            <div className="h-full bg-green-500 animate-[loading_1.5s_ease-in-out_infinite]"></div>
          </div>
          <div className="mt-4 text-green-400 text-xs terminal-text typing-effect">
            Loading ALIENTELLIGENCE/predictivethreatdetection...
          </div>
        </div>
      ) : (
        <>
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((message, index) => (
              <div
                key={index}
                className={`flex ${
                  message.role === "user"
                    ? "justify-end"
                    : message.role === "system"
                      ? "justify-center"
                      : "justify-start"
                }`}
              >
                <div
                  className={`max-w-[85%] rounded px-4 py-2 ${
                    message.role === "user"
                      ? "bg-green-700/30 border border-green-500/30 text-green-100"
                      : message.role === "system"
                        ? "bg-black/70 border border-green-500/40 text-green-500 text-xs"
                        : "bg-black/50 border border-green-500/20 text-green-400"
                  } terminal-text`}
                >
                  {message.content}
                </div>
              </div>
            ))}

            {isLoading && (
              <div className="flex justify-start">
                <div className="max-w-[80%] rounded px-4 py-2 bg-black/50 border border-green-500/20 text-green-400">
                  <div className="flex items-center space-x-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="terminal-text">Processing query...</span>
                  </div>
                </div>
              </div>
            )}

            {error && (
              <div className="flex justify-center">
                <div className="max-w-[80%] rounded px-4 py-2 bg-red-900/20 border border-red-500/30 text-red-300">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="terminal-text">{error}</span>
                  </div>
                </div>
              </div>
            )}

            {messages.length === 1 && !isLoading && showExamples && (
              <div className="mt-4">
                <SecurityChatExamples onSelectExample={handleExampleSelect} />
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="p-4 border-t border-green-500/30">
            <div className="flex space-x-2">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Enter security query..."
                className="terminal-text bg-black/50 border-green-500/30 focus:border-green-500 focus:ring-green-500/30"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !isLoading) {
                    handleSendMessage()
                  }
                }}
                disabled={isLoading || isInitializing}
              />
              <Button
                onClick={handleSendMessage}
                disabled={isLoading || !input.trim() || isInitializing}
                className="bg-green-700 hover:bg-green-600 text-green-100"
              >
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
