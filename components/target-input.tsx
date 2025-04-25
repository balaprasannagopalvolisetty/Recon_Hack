"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Loader2, Target } from "lucide-react"

interface TargetInputProps {
  url: string
  setUrl: (url: string) => void
  onScan: () => void
  isScanning: boolean
}

export const TargetInput = ({ url, setUrl, onScan, isScanning }: TargetInputProps) => {
  const [isValid, setIsValid] = useState(true)

  const validateUrl = (input: string) => {
    // Basic URL validation
    if (!input) {
      setIsValid(false)
      return
    }

    // Allow domain names without protocol
    const urlPattern = /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/
    setIsValid(urlPattern.test(input))
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value
    setUrl(input)
    validateUrl(input)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (isValid && url && !isScanning) {
      onScan()
    }
  }

  return (
    <div className="w-full max-w-3xl mx-auto">
      <div className="text-center mb-6">
        <h2 className="glitch text-xl sm:text-2xl font-bold text-green-500 mb-2" data-text="Target URL">
          Target URL
        </h2>
        <p className="text-green-400 terminal-text text-sm sm:text-base">
          Enter a domain or URL to begin reconnaissance (e.g., example.com)
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
        <div className="relative flex-grow">
          <Input
            type="text"
            placeholder="Enter domain or URL (e.g., example.com)"
            value={url}
            onChange={handleChange}
            className={`h-12 pl-4 pr-10 text-base terminal-text bg-black/50 border-green-500/50 focus:border-green-500 focus:ring-green-500/30 ${
              !isValid && url ? "border-red-500" : ""
            }`}
            disabled={isScanning}
          />
          {!isValid && url && <p className="text-red-500 text-sm mt-1">Please enter a valid domain or URL</p>}
        </div>

        <Button
          type="submit"
          disabled={!isValid || !url || isScanning}
          className="h-12 px-6 bg-green-700 hover:bg-green-600 text-green-100 border border-green-500/50 cyber-glow"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning
            </>
          ) : (
            <>
              <Target className="mr-2 h-4 w-4" />
              Scan
            </>
          )}
        </Button>
      </form>
    </div>
  )
}
