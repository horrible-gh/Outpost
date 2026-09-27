package patrol

import (
	"strings"
	"testing"
)

func TestRenderMarkdownRendersCommonJournalSyntax(t *testing.T) {
	raw := "# Patrol 17\n\n" +
		"**Summary:** healthy\n\n" +
		"- checked logs\n- checked ports\n\n" +
		"| Item | Result |\n| --- | --- |\n| CPU | 4.2% |\n\n" +
		"> follow up tomorrow\n\n" +
		"```text\nhello <world>\n```\n"
	html := renderMarkdown(raw)
	for _, want := range []string{
		"<h1>Patrol 17</h1>",
		"<strong>Summary:</strong> healthy",
		"<ul><li>checked logs</li><li>checked ports</li></ul>",
		"<table>",
		"<td>4.2%</td>",
		"<blockquote>follow up tomorrow</blockquote>",
		"&lt;world&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected rendered markdown to contain %q, got %s", want, html)
		}
	}
}

func TestRenderMarkdownEscapesHTMLAndUnsafeLinks(t *testing.T) {
	raw := `<script>alert(1)</script>

[bad](javascript:alert(1))
[good](https://example.com)
`
	html := renderMarkdown(raw)
	if strings.Contains(html, "<script>") {
		t.Fatalf("raw html must be escaped: %s", html)
	}
	if strings.Contains(html, `href="javascript:`) {
		t.Fatalf("unsafe markdown URL rendered as a link: %s", html)
	}
	if !strings.Contains(html, `href="https://example.com"`) {
		t.Fatalf("safe HTTPS link should render: %s", html)
	}
}
