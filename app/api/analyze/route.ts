import { NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export async function POST(request: Request) {
  try {
    const { query, scanResult } = await request.json()

    if (!query || !scanResult) {
      return NextResponse.json({ error: "Query and scan result are required" }, { status: 400 })
    }

    // Create a prompt based on the scan result and user query
    const prompt = `
You are a cybersecurity expert analyzing web reconnaissance results.
The scan was performed on the domain: ${scanResult.domain}

Here's a summary of the scan results:
${JSON.stringify(scanResult, null, 2)}

User query: ${query}

Provide a detailed analysis based on the scan results and the user's query.
Focus on security implications, potential vulnerabilities, and recommendations.
Be concise but thorough.
`

    // Generate a response using the OpenAI API
    const { text } = await generateText({
      model: openai("gpt-4o"),
      prompt,
      maxTokens: 500,
    })

    return NextResponse.json({ response: text })
  } catch (error) {
    console.error("Analysis error:", error)
    return NextResponse.json({ error: "Failed to generate analysis" }, { status: 500 })
  }
}
