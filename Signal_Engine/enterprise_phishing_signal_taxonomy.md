# Enterprise-Grade Phishing Signal Taxonomy

Version: 1.0

This document provides a comprehensive taxonomy of phishing detection
signals categorized into:

-   **Deterministic Signals** --- Can be derived strictly from the
    `.eml` file contents without external queries.
-   **Non-Deterministic Signals** --- Require external enrichment (DNS,
    reputation, WHOIS, threat intel, sandboxing, etc.).

Each signal includes a short description to support downstream playbook
design for an AI investigation agent.

------------------------------------------------------------------------

# 1. Identity & Header Integrity Signals

## Deterministic

### identity.reply_to_mismatch

Reply-To domain differs from From domain, commonly used to redirect
victim responses to attacker-controlled inboxes.

### identity.display_name_spoof

Display name impersonates a known executive/vendor while actual email
address differs.

### identity.return_path_mismatch

Return-Path domain does not match visible From domain, suggesting
spoofed envelope sender.

### identity.from_domain_mismatch_in_headers

Domain inconsistencies between From, Message-ID, or other header
domains.

### header.missing_message_id

Missing or malformed Message-ID header, often seen in poorly constructed
phishing emails.

### header.received_chain_anomaly

Irregularities in Received headers (out-of-order timestamps, private IPs
in public chain).

### header.x_originating_ip_present

Presence of X-Originating-IP header may reveal actual sender IP.

### header.priority_flag_set

High priority/importance flag set to induce urgency.

### header.suspicious_user_agent

Suspicious or uncommon mail client identifiers in headers.

------------------------------------------------------------------------

## Non-Deterministic

### identity.domain_not_owned_by_org

From domain not owned by legitimate organization (requires org inventory
check).

### identity.newly_registered_sender_domain

Sender domain recently registered (requires WHOIS lookup).

### identity.lookalike_domain_confirmed

Domain visually similar to legitimate brand (requires brand database
comparison).

------------------------------------------------------------------------

# 2. Authentication Signals (SPF / DKIM / DMARC)

## Deterministic

### auth.spf_fail

SPF result explicitly shows fail in Authentication-Results header.

### auth.dkim_fail

DKIM signature validation result indicates failure.

### auth.dmarc_fail

DMARC policy evaluation result is fail.

### auth.alignment_fail

Domain alignment failure between SPF/DKIM and From domain.

------------------------------------------------------------------------

## Non-Deterministic

### auth.missing_spf_record

No SPF record exists for sending domain (requires DNS query).

### auth.missing_dmarc_record

No DMARC record published (requires DNS query).

------------------------------------------------------------------------

# 3. URL & Link Analysis Signals

## Deterministic

### url.shortener_used

Use of URL shortening services (bit.ly, tinyurl, etc.).

### url.ip_literal_used

URL uses raw IP address instead of domain.

### url.display_text_mismatch

Visible hyperlink text differs from actual href target.

### url.multiple_redirect_pattern_in_path

Suspicious redirect-like parameters embedded in URL path.

### url.long_obfuscated_string

Excessively long random-looking path or query string.

### url.punycode_present

Punycode encoding detected (possible IDN homograph).

### url.embedded_at_symbol

URL contains @ symbol to obscure real destination.

### url.javascript_in_link

Use of javascript: or data: schemes in link.

------------------------------------------------------------------------

## Non-Deterministic

### url.reputation_malicious

External reputation provider flags URL as malicious.

### url.redirect_chain_detected

External resolution shows multiple redirections.

### url.domain_newly_registered

Domain age below threshold.

### url.hosting_on_free_provider

Domain hosted on free hosting infrastructure.

------------------------------------------------------------------------

# 4. Content & Social Engineering Signals

## Deterministic

### content.credential_harvest_language

Language requesting login credentials or password reset.

### content.urgency_language

Phrases invoking urgency, threat, or immediate action.

### content.payment_or_invoice_lure

Mentions invoices, wire transfers, payment changes.

### content.account_suspension_threat

Claims account will be suspended or locked.

### content.generic_greeting

Use of non-personalized greeting (e.g., "Dear user").

### content.brand_impersonation

Brand logos/text inconsistent with sending domain.

### content.grammar_spelling_errors

Obvious grammar/spelling anomalies.

### content.html_form_embedded

HTML contains embedded input forms.

### content.hidden_text_or_css

Text hidden via CSS styling.

------------------------------------------------------------------------

## Non-Deterministic

### content.similarity_to_known_campaign

Matches known phishing template (requires campaign database).

### content.nlp_anomaly_score_high

High anomaly score from trained NLP classifier.

------------------------------------------------------------------------

# 5. Attachment Signals

## Deterministic

### attachment.suspicious_file_type

Attachment types commonly abused (.html, .iso, .lnk, .xlsm, etc.).

### attachment.double_extension

Filename uses double extension (e.g., invoice.pdf.exe).

### attachment.contains_macro_indicator

Static indicators of macro presence in Office file.

### attachment.password_protected_archive

Archive flagged as encrypted or password-protected.

### attachment.embedded_urls

URLs extracted from document contents.

------------------------------------------------------------------------

## Non-Deterministic

### attachment.hash_known_malicious

Hash matches known malicious sample database.

### attachment.sandbox_behavior_malicious

Sandbox detonation shows malicious behavior.

------------------------------------------------------------------------

# 6. Infrastructure & Technical Indicators

## Deterministic

### infra.private_ip_in_received_chain

Private/internal IP found in unexpected header chain.

### infra.timezone_mismatch_in_headers

Timestamp inconsistencies across Received headers.

------------------------------------------------------------------------

## Non-Deterministic

### infra.sending_ip_reputation_bad

Sender IP flagged by reputation feeds.

### infra.malicious_mx_records

MX records associated with known malicious infrastructure.

### infra.bulletproof_hosting_detected

Domain hosted on bulletproof infrastructure provider.

------------------------------------------------------------------------

# 7. Behavioral & Contextual Signals

## Deterministic

### behavior.unusual_time_of_day_pattern

Email sent at atypical hour relative to sender display context.

### behavior.bulk_recipient_pattern

High recipient count visible in headers.

------------------------------------------------------------------------

## Non-Deterministic

### behavior.user_not_previous_correspondent

Sender has no prior history with recipient (requires mailbox history).

### behavior.multiple_similar_messages_detected

Campaign clustering across organization.

------------------------------------------------------------------------

# 8. Advanced Evasion Signals

## Deterministic

### evasion.base64_encoded_html

Large base64-encoded HTML blocks in body.

### evasion.zero_width_characters

Use of zero-width Unicode characters for obfuscation.

### evasion.homoglyph_substitution

Homoglyph characters replacing ASCII letters.

------------------------------------------------------------------------

## Non-Deterministic

### evasion.domain_fast_flux_behavior

Rapid DNS changes observed.

### evasion.cdn_abuse_detected

Domain fronting or CDN abuse identified.

------------------------------------------------------------------------

# Summary

This taxonomy provides structured inputs for:

-   Signal generation (LLM bounded template)
-   Deterministic scoring engine
-   Playbook selection logic
-   Agentic investigation branching

Each signal should map to: - Evidence source (envelope/tool) - Weight in
scoring model - Associated investigation playbook(s)
