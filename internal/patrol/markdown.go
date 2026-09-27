package patrol

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

var (
	mdHeadingRE     = regexp.MustCompile(`^(#{1,6})\s+(.+)$`)
	mdUnorderedRE   = regexp.MustCompile(`^[-*+]\s+(.+)$`)
	mdOrderedRE     = regexp.MustCompile(`^\d+[.)]\s+(.+)$`)
	mdCodeSpanRE    = regexp.MustCompile("`([^`\n]+)`")
	mdLinkRE        = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	mdBoldRE        = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdStrikeRE      = regexp.MustCompile(`~~([^~]+)~~`)
	mdEmRE          = regexp.MustCompile(`\*([^*]+)\*`)
	mdTableDivider  = regexp.MustCompile(`^:?-{3,}:?$`)
	mdLanguageClean = regexp.MustCompile(`[^A-Za-z0-9_+.-]`)
)

func renderMarkdown(markdown string) string {
	markdown = strings.ReplaceAll(markdown, "\r\n", "\n")
	markdown = strings.ReplaceAll(markdown, "\r", "\n")
	lines := strings.Split(markdown, "\n")

	var out strings.Builder
	var paragraph []string
	var code []string
	inCode := false
	codeLang := ""
	listKind := ""

	flushParagraph := func() {
		if len(paragraph) == 0 {
			return
		}
		out.WriteString("<p>")
		for i, line := range paragraph {
			if i > 0 {
				out.WriteByte(' ')
			}
			out.WriteString(renderMarkdownInline(strings.TrimSpace(line)))
		}
		out.WriteString("</p>")
		paragraph = nil
	}
	closeList := func() {
		switch listKind {
		case "ul":
			out.WriteString("</ul>")
		case "ol":
			out.WriteString("</ol>")
		}
		listKind = ""
	}
	flushCode := func() {
		class := ""
		if codeLang != "" {
			lang := mdLanguageClean.ReplaceAllString(codeLang, "")
			if lang != "" {
				class = ` class="language-` + html.EscapeString(lang) + `"`
			}
		}
		out.WriteString("<div class=\"md-code\"><pre><code")
		out.WriteString(class)
		out.WriteString(">")
		out.WriteString(html.EscapeString(strings.Join(code, "\n")))
		out.WriteString("</code></pre></div>")
		code = nil
		codeLang = ""
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			if inCode {
				flushCode()
				inCode = false
			} else {
				flushParagraph()
				closeList()
				inCode = true
				codeLang = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			}
			continue
		}
		if inCode {
			code = append(code, line)
			continue
		}

		if trimmed == "" {
			flushParagraph()
			closeList()
			continue
		}

		if i+1 < len(lines) && isMarkdownTableHeader(trimmed, strings.TrimSpace(lines[i+1])) {
			flushParagraph()
			closeList()
			headers := splitMarkdownTableRow(trimmed)
			out.WriteString("<div class=\"md-table-wrap\"><table><thead><tr>")
			for _, cell := range headers {
				out.WriteString("<th>")
				out.WriteString(renderMarkdownInline(cell))
				out.WriteString("</th>")
			}
			out.WriteString("</tr></thead><tbody>")
			i += 2
			for ; i < len(lines); i++ {
				row := strings.TrimSpace(lines[i])
				if row == "" || !strings.Contains(row, "|") {
					i--
					break
				}
				cells := splitMarkdownTableRow(row)
				out.WriteString("<tr>")
				for col := 0; col < len(headers); col++ {
					value := ""
					if col < len(cells) {
						value = cells[col]
					}
					out.WriteString("<td>")
					out.WriteString(renderMarkdownInline(value))
					out.WriteString("</td>")
				}
				out.WriteString("</tr>")
			}
			out.WriteString("</tbody></table></div>")
			continue
		}

		if match := mdHeadingRE.FindStringSubmatch(trimmed); len(match) == 3 {
			flushParagraph()
			closeList()
			level := len(match[1])
			fmt.Fprintf(&out, "<h%d>%s</h%d>", level, renderMarkdownInline(match[2]), level)
			continue
		}

		if isMarkdownRule(trimmed) {
			flushParagraph()
			closeList()
			out.WriteString("<hr>")
			continue
		}

		if strings.HasPrefix(trimmed, ">") {
			flushParagraph()
			closeList()
			quote := strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))
			out.WriteString("<blockquote>")
			out.WriteString(renderMarkdownInline(quote))
			out.WriteString("</blockquote>")
			continue
		}

		if match := mdUnorderedRE.FindStringSubmatch(trimmed); len(match) == 2 {
			flushParagraph()
			if listKind != "ul" {
				closeList()
				out.WriteString("<ul>")
				listKind = "ul"
			}
			out.WriteString("<li>")
			out.WriteString(renderMarkdownInline(match[1]))
			out.WriteString("</li>")
			continue
		}

		if match := mdOrderedRE.FindStringSubmatch(trimmed); len(match) == 2 {
			flushParagraph()
			if listKind != "ol" {
				closeList()
				out.WriteString("<ol>")
				listKind = "ol"
			}
			out.WriteString("<li>")
			out.WriteString(renderMarkdownInline(match[1]))
			out.WriteString("</li>")
			continue
		}

		closeList()
		paragraph = append(paragraph, line)
	}

	if inCode {
		flushCode()
	}
	flushParagraph()
	closeList()
	return out.String()
}

func renderMarkdownInline(value string) string {
	var codes []string
	value = mdCodeSpanRE.ReplaceAllStringFunc(value, func(match string) string {
		parts := mdCodeSpanRE.FindStringSubmatch(match)
		codes = append(codes, "<code>"+html.EscapeString(parts[1])+"</code>")
		return fmt.Sprintf("@@OUTPOST_CODE_%d@@", len(codes)-1)
	})

	value = html.EscapeString(value)
	value = mdLinkRE.ReplaceAllStringFunc(value, func(match string) string {
		parts := mdLinkRE.FindStringSubmatch(match)
		if len(parts) != 3 || !safeMarkdownURL(html.UnescapeString(parts[2])) {
			return match
		}
		href := html.EscapeString(html.UnescapeString(parts[2]))
		return `<a href="` + href + `" target="_blank" rel="noopener noreferrer">` + parts[1] + `</a>`
	})
	value = mdBoldRE.ReplaceAllString(value, "<strong>$1</strong>")
	value = mdStrikeRE.ReplaceAllString(value, "<del>$1</del>")
	value = mdEmRE.ReplaceAllString(value, "<em>$1</em>")
	for i, code := range codes {
		value = strings.ReplaceAll(value, fmt.Sprintf("@@OUTPOST_CODE_%d@@", i), code)
	}
	return value
}

func safeMarkdownURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "#") {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "mailto":
		return true
	default:
		return false
	}
}

func isMarkdownRule(value string) bool {
	compact := strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "\t", "")
	return compact == "---" || compact == "***" || compact == "___"
}

func isMarkdownTableHeader(header, divider string) bool {
	if !strings.Contains(header, "|") || !strings.Contains(divider, "|") {
		return false
	}
	cells := splitMarkdownTableRow(divider)
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		if !mdTableDivider.MatchString(strings.TrimSpace(cell)) {
			return false
		}
	}
	return true
}

func splitMarkdownTableRow(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "|")
	value = strings.TrimSuffix(value, "|")
	parts := strings.Split(value, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
