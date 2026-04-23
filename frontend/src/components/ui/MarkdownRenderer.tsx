"use client";

import ReactMarkdown from "react-markdown";

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

export function MarkdownRenderer({ content, className = "" }: MarkdownRendererProps) {
  if (!content) {
    return null;
  }

  return (
    <article className={`prose prose-slate dark:prose-invert prose-sm max-w-none ${className}`}>
      <ReactMarkdown>{content}</ReactMarkdown>
    </article>
  );
}
