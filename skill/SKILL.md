---
name: gmail-proxy
description: >
  Read-only access to Gmail through a security proxy. Use when the user asks
  about email, wants to search messages, read threads, or check for new mail.
  All results are pre-filtered and scrubbed — security-sensitive emails
  (MFA codes, password resets, etc.) are excluded automatically.
---

# Gmail Proxy

Read-only email access via a local security proxy listening on a Unix domain socket
at `/var/run/gmail-proxy/proxy.sock`. The proxy enforces label-based filtering and
content scrubbing. You cannot send, delete, or modify any email through this interface.

## Search emails

```bash
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=QUERY&max=N'
```

- `q`: Gmail search query (URL-encoded)
- `max`: maximum results (default 20, max 100)
- Returns: JSON array of messages with `id`, `thread_id`, `from`, `to`, `subject`, `date`, `snippet`, `body_text`, `labels`, `has_attachments`

### Supported query syntax

**Terms and phrases:**
- Bare words: `invoice quarterly` (implicit AND)
- Quoted phrases: `"project proposal"`
- OR: `from:alice OR from:bob`
- Negation: `-from:noreply@example.com`
- Grouping: `(from:alice OR from:bob) subject:meeting`

**Supported operators:**
- `from:`, `to:`, `cc:`, `bcc:` — sender/recipient
- `subject:` — subject line
- `has:attachment` — messages with attachments
- `filename:pdf` — attachment filename
- `newer_than:7d`, `older_than:30d` — relative time (d=days, m=months, y=years)
- `after:2026/01/01`, `before:2026/03/01` — absolute dates
- `category:promotions` — Gmail category
- `size:`, `larger:`, `smaller:` — message size
- `is:unread`, `is:read`, `is:starred` — message state
- `list:` — mailing list header
- `deliveredto:` — delivered-to address
- `rfc822msgid:` — message ID header

**Not available** (restricted by proxy):
- `label:` — labels are managed by the proxy for security filtering
- `in:anywhere`, `in:trash`, `in:spam` — restricted locations
- `is:draft` — drafts are not accessible

If your query has a syntax error, the proxy returns a JSON error with a
`hint` field explaining what went wrong and how to fix it. Read the hint
and adjust your query accordingly.

### Examples

```bash
# Recent unread
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=is:unread+newer_than:1d&max=10'

# From a specific sender
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=from:jane@example.com&max=5'

# Keyword search
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=project+proposal+has:attachment&max=10'
```

### Pagination

Search results are paginated. The response includes a `next_page_token` field.
To get the next page, pass it back:

```bash
# First page
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=from:amazon&max=20'
# Response includes: "next_page_token": "abc123..."

# Next page
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock 'http://localhost/search?q=from:amazon&max=20&page_token=abc123...'
```

Keep paging until `next_page_token` is null. The `result_size_estimate` field
gives an approximate total count.

## Read a single message

```bash
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock http://localhost/message/MESSAGE_ID
```

- Returns: single message object with full `body_text`

## Read a thread

```bash
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock http://localhost/thread/THREAD_ID
```

- Returns: JSON object with `thread_id` and `messages` array, ordered chronologically

## Check proxy health

```bash
curl -s --unix-socket /var/run/gmail-proxy/proxy.sock http://localhost/health
```

- Returns: watch status, token freshness, poller status

## Important notes

- All results are **read-only** — there is no way to send, reply, archive, label, or delete.
- Security-sensitive emails (2FA codes, password resets, verification links) are
  **automatically excluded** by the proxy. You will never see them in results.
  Do not attempt to search for them or work around this restriction.
- Links in email bodies may be redacted by the proxy if they match
  authentication/reset URL patterns. This is intentional.
- HTML bodies are not available. Only plain text content is returned.
- If search returns no results, the emails may exist but be filtered.
  Do not tell the user the emails don't exist — say the proxy may be filtering them.
