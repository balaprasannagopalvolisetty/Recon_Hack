import { NextResponse } from "next/server"

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export async function POST(request: Request) {
  try {
    const { message, scanData } = await request.json()

    // Prepare the prompt with context from scan data if available
    let prompt = message
    if (scanData) {
      prompt = `
I'm analyzing the following target: ${scanData.domain || "unknown"}
Scan results summary: ${JSON.stringify(scanData).substring(0, 500)}...

User query: ${message}

Please provide a detailed security analysis based on this information.
      `
    }

    // Call the backend API that interfaces with Ollama
    const response = await fetch(`${API_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: prompt,
        model: "ALIENTELLIGENCE/predictivethreatdetection",
      }),
    })

    if (!response.ok) {
      const errorData = await response.json()
      return NextResponse.json(
        { error: errorData.detail || "Failed to get response from AI" },
        { status: response.status },
      )
    }

    const data = await response.json()
    return NextResponse.json({ response: data.analysis || data.message || "No response from model" })
  } catch (error) {
    console.error("Error in chat API route:", error)
    return NextResponse.json({ error: "Failed to communicate with AI model" }, { status: 500 })
  }
}
