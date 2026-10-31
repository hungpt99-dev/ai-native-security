import { useState } from "react";
import { Bot, Send, User } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { PageHeader, ErrorState } from "@/components/common";
import { useAiHealth, useAskAssistant } from "@/hooks/queries";
import type { AssistantReply } from "@/lib/types";

const SUGGESTIONS = [
  "Which repositories have the highest security risk?",
  "Which findings are actively exploited?",
  "Which remediation proposals are not verified yet?",
  "Why was the risk of the top finding assessed that way?",
];

type Turn = { role: "user" | "assistant"; text: string; reply?: AssistantReply; error?: string };

export function AssistantPage() {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [conversationId, setConversationId] = useState<string | undefined>(undefined);
  const ask = useAskAssistant();
  const { data: health } = useAiHealth();

  const submit = () => {
    const text = question.trim();
    if (!text) return;
    setTurns((previous) => [...previous, { role: "user", text }]);
    setQuestion("");
    ask.mutate(
      { question: text, conversation_id: conversationId },
      {
        onSuccess: (reply) => {
          setConversationId(reply.conversation_id);
          setTurns((previous) => [...previous, { role: "assistant", text: reply.answer, reply }]);
        },
        onError: (error) => {
          setTurns((previous) => [
            ...previous,
            { role: "assistant", text: "The assistant could not answer.", error: String(error.message) },
          ]);
        },
      },
    );
  };

  return (
    <div>
      <PageHeader
        title="Security assistant"
        subtitle="Answers are grounded in retrieved platform data — not in model memory"
        actions={
          <Badge tone={health?.configured ? "success" : "info"}>
            {health?.configured ? `${health.provider}/${health.model}` : "AI not configured"}
          </Badge>
        }
      />

      <Card className="mb-4">
        <div className="max-h-[55vh] space-y-3 overflow-auto p-4">
          {turns.length === 0 ? (
            <div className="space-y-2">
              <p className="text-sm text-slate-400">Ask about your posture. The assistant can read:</p>
              <ul className="space-y-1 text-xs text-slate-500">
                <li>· findings, severities and KEV status</li>
                <li>· risk assessments and why they were produced</li>
                <li>· remediation proposals and their verification state</li>
                <li>· scans, assets and recorded decisions</li>
              </ul>
              <div className="flex flex-wrap gap-2 pt-2">
                {SUGGESTIONS.map((suggestion) => (
                  <Button
                    key={suggestion}
                    size="sm"
                    variant="outline"
                    onClick={() => setQuestion(suggestion)}
                  >
                    {suggestion}
                  </Button>
                ))}
              </div>
            </div>
          ) : null}

          {turns.map((turn, index) => (
            <div key={index} className="flex gap-2">
              <div className="mt-0.5 text-slate-500">
                {turn.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4 text-cyan-400" />}
              </div>
              <div className="min-w-0 flex-1">
                <p className="whitespace-pre-wrap text-sm text-slate-200">{turn.text}</p>
                {turn.reply ? (
                  <div className="mt-2 space-y-1 text-xs text-slate-500">
                    <div className="flex flex-wrap gap-1">
                      {turn.reply.tool_results.map((tool, toolIndex) => (
                        <Badge key={`${tool.tool}-${toolIndex}`} tone={tool.error ? "danger" : "neutral"}>
                          {tool.tool} · {tool.count}
                        </Badge>
                      ))}
                    </div>
                    {turn.reply.cited_finding_ids.length ? (
                      <p className="font-mono text-[11px]">
                        cited findings: {turn.reply.cited_finding_ids.map((id) => id.slice(0, 8)).join(", ")}
                      </p>
                    ) : null}
                    {turn.reply.data_gaps.length ? (
                      <p className="text-amber-300">Data gaps: {turn.reply.data_gaps.join("; ")}</p>
                    ) : null}
                  </div>
                ) : null}
                {turn.error ? <p className="mt-1 text-xs text-rose-300">{turn.error}</p> : null}
              </div>
            </div>
          ))}
          {ask.isPending ? <p className="text-xs text-slate-500">Retrieving data and reasoning…</p> : null}
        </div>
      </Card>

      {!health?.configured ? (
        <p className="mb-2 text-xs text-amber-300">
          No AI provider is configured. Set ANS_AI_ENABLED=true and ANS_AI_API_KEY to use the assistant.
        </p>
      ) : null}

      <div className="flex gap-2">
        <textarea
          className="min-h-[64px] flex-1 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-200 outline-none focus:border-cyan-500/60"
          placeholder="Ask a question about your security posture…"
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              submit();
            }
          }}
        />
        <Button onClick={submit} disabled={ask.isPending || !question.trim()}>
          <Send className="h-4 w-4" /> Ask
        </Button>
      </div>
      {ask.error && !turns.length ? <ErrorState error={ask.error} /> : null}
    </div>
  );
}
