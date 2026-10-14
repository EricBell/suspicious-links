use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedLink {
    pub start: usize,
    pub end: usize,
    pub original_link: String,
}

// Regex patterns
static SCHEME_URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches URI schemes like http://, https://, mail://, ftp://, file://, etc.
    Regex::new(r##"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"'{}|\\^`]+"##).unwrap()
});

static MAILTO_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches mailto: links without slashes, e.g. mailto:user@example.com
    Regex::new(r##"(?i)\bmailto:[^\s<>"'{}|\\^`]+"##).unwrap()
});

static WWW_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches bare www URLs without scheme
    Regex::new(r##"(?i)\bwww\.[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>"'{}|\\^`]*)*"##).unwrap()
});

static HTML_HREF_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches href="..." or href='...'
    Regex::new(r#"(?i)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')(?:\s*>)?"#).unwrap()
});

static MARKDOWN_LINK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches [text](url) or [text](url "title")
    Regex::new(r#"\[[^\]]*\]\(\s*([^\s)]+)(?:\s+["'][^"']*["'])?\s*\)"#).unwrap()
});

/// Trims common trailing punctuation from bare URLs that are often part of the surrounding sentence.
fn trim_trailing_punctuation(raw_url: &str) -> &str {
    let mut s = raw_url;
    while !s.is_empty() {
        let last_char = s.chars().next_back().unwrap();
        match last_char {
            '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | '>' | ']' => {
                s = &s[..s.len() - last_char.len_utf8()];
            }
            ')' => {
                // If the URL has an unmatched closing parenthesis, trim it
                let open_count = s.chars().filter(|&c| c == '(').count();
                let close_count = s.chars().filter(|&c| c == ')').count();
                if close_count > open_count {
                    s = &s[..s.len() - last_char.len_utf8()];
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    s
}

/// Identifies all hyperlinks in the text in textual order without overlapping spans.
pub fn find_links(text: &str, replacement_token: &str) -> Vec<DetectedLink> {
    let mut raw_candidates: Vec<DetectedLink> = Vec::new();

    // 1. Markdown links: [text](url)
    for cap in MARKDOWN_LINK_REGEX.captures_iter(text) {
        if let Some(url_match) = cap.get(1) {
            let url_str = url_match.as_str();
            if url_str != replacement_token && !url_str.is_empty() {
                raw_candidates.push(DetectedLink {
                    start: url_match.start(),
                    end: url_match.end(),
                    original_link: url_str.to_string(),
                });
            }
        }
    }

    // 2. HTML href attributes: href="..." or href='...'
    for cap in HTML_HREF_REGEX.captures_iter(text) {
        let target = cap.get(1).or_else(|| cap.get(2));
        if let Some(target_match) = target {
            let link_val = target_match.as_str();
            if link_val != replacement_token && !link_val.is_empty() {
                raw_candidates.push(DetectedLink {
                    start: target_match.start(),
                    end: target_match.end(),
                    original_link: link_val.to_string(),
                });
            }
        }
    }

    // 3. Scheme-based URLs: https://..., mail://..., ftp://..., etc.
    for m in SCHEME_URL_REGEX.find_iter(text) {
        let raw = m.as_str();
        let trimmed = trim_trailing_punctuation(raw);
        if trimmed != replacement_token && !trimmed.is_empty() {
            let end_offset = m.start() + trimmed.len();
            raw_candidates.push(DetectedLink {
                start: m.start(),
                end: end_offset,
                original_link: trimmed.to_string(),
            });
        }
    }

    // 4. Mailto links: mailto:...
    for m in MAILTO_REGEX.find_iter(text) {
        let raw = m.as_str();
        let trimmed = trim_trailing_punctuation(raw);
        if trimmed != replacement_token && !trimmed.is_empty() {
            let end_offset = m.start() + trimmed.len();
            raw_candidates.push(DetectedLink {
                start: m.start(),
                end: end_offset,
                original_link: trimmed.to_string(),
            });
        }
    }

    // 5. Bare www links: www.example.com
    for m in WWW_REGEX.find_iter(text) {
        let raw = m.as_str();
        let trimmed = trim_trailing_punctuation(raw);
        if trimmed != replacement_token && !trimmed.is_empty() {
            let end_offset = m.start() + trimmed.len();
            raw_candidates.push(DetectedLink {
                start: m.start(),
                end: end_offset,
                original_link: trimmed.to_string(),
            });
        }
    }

    // Sort by start position ascending, then longer span first (descending by end)
    raw_candidates.sort_by(|a, b| {
        a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end))
    });

    // Merge/deduplicate overlapping candidates in document order
    let mut resolved: Vec<DetectedLink> = Vec::new();
    for candidate in raw_candidates {
        if let Some(last) = resolved.last() {
            // Check if this candidate overlaps with the last accepted candidate
            if candidate.start < last.end {
                // If they have the exact same start and candidate is contained within or equal, skip
                // We keep the earlier or wider match
                continue;
            }
        }
        resolved.push(candidate);
    }

    resolved
}

/// Replaces all detected links with `replacement_token`, returning the new text
/// and the list of detected links in file order.
pub fn replace_links(text: &str, replacement_token: &str) -> (String, Vec<DetectedLink>) {
    let links = find_links(text, replacement_token);
    if links.is_empty() {
        return (text.to_string(), Vec::new());
    }

    let mut result = String::with_capacity(text.len());
    let mut last_idx = 0;

    for link in &links {
        result.push_str(&text[last_idx..link.start]);
        result.push_str(replacement_token);
        last_idx = link.end;
    }
    result.push_str(&text[last_idx..]);

    (result, links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_example_north_txt() {
        let text = "Here is an email mail://eric@ericbell.net and a weblink https://polymorph.co.";
        let (replaced, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(
            replaced,
            "Here is an email [Suspicious Link Removed] and a weblink [Suspicious Link Removed]."
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].original_link, "mail://eric@ericbell.net");
        assert_eq!(links[1].original_link, "https://polymorph.co");
    }

    #[test]
    fn test_order_preserved() {
        let text = "First https://first.com then mail://second@test.com then ftp://third.org/file";
        let (_, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(links.len(), 3);
        assert_eq!(links[0].original_link, "https://first.com");
        assert_eq!(links[1].original_link, "mail://second@test.com");
        assert_eq!(links[2].original_link, "ftp://third.org/file");
    }

    #[test]
    fn test_html_href() {
        let text = r#"<p>Visit <a href="https://example.com/page.html">this page</a> or <a href="local.html">local</a></p>"#;
        let (replaced, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(
            replaced,
            r#"<p>Visit <a href="[Suspicious Link Removed]">this page</a> or <a href="[Suspicious Link Removed]">local</a></p>"#
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].original_link, "https://example.com/page.html");
        assert_eq!(links[1].original_link, "local.html");
    }

    #[test]
    fn test_markdown_links() {
        let text = "Check out [Poly](https://polymorph.co) and [Internal](docs/spec.html) now.";
        let (replaced, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(
            replaced,
            "Check out [Poly]([Suspicious Link Removed]) and [Internal]([Suspicious Link Removed]) now."
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].original_link, "https://polymorph.co");
        assert_eq!(links[1].original_link, "docs/spec.html");
    }

    #[test]
    fn test_punctuation_trimming() {
        let text = "See https://example.com, (https://example.org/path), and https://test.org/wiki/Foo_(bar).";
        let (replaced, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(links.len(), 3);
        assert_eq!(links[0].original_link, "https://example.com");
        assert_eq!(links[1].original_link, "https://example.org/path");
        assert_eq!(links[2].original_link, "https://test.org/wiki/Foo_(bar)");
        assert_eq!(
            replaced,
            "See [Suspicious Link Removed], ([Suspicious Link Removed]), and [Suspicious Link Removed]."
        );
    }

    #[test]
    fn test_idempotent_no_double_replace() {
        let text = "Here is [Suspicious Link Removed] already.";
        let (replaced, links) = replace_links(text, "[Suspicious Link Removed]");

        assert_eq!(replaced, text);
        assert!(links.is_empty());
    }
}
