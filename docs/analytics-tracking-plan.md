# Analytics tracking plan

Last updated: 2026-07-17

## Scope

The browser implementation sends the same canonical product events to PostHog
and Google Tag Manager container `GTM-5X8L82L8` after explicit analytics
consent. GTM receives them as `dataLayer` custom events and is responsible for
forwarding them to GA4. The browser does not send raw repository names, search
text, job IDs, findings, CVE or commit identifiers, artifact URLs, or feedback
messages.

`$pageview` in PostHog and `page_view` in GA4 represent the `visitor` stage.
Repository result paths are reported as `/r/:owner/:repository`; query strings
and raw referrers are excluded.

## Canonical events

| Funnel stage                  | Trigger                                                                           | Primary properties                                                                         |
| ----------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `visitor`                     | First consented page view                                                         | `surface`, `route_template`, `session_entry`, `referrer_category`                          |
| `repository_search_started`   | First debounced suggestion request after the input reaches two characters         | `input_type`, `provider_guess`, `query_length_bucket`, `search_surface`                    |
| `valid_repository_selected`   | A suggestion, recent context, or normalized direct input passes client validation | `selection_method`, `provider`, `existing_context`, `candidate_position`                   |
| `scan_requested`              | Immediately before a valid scan POST                                              | `scan_attempt_id`, `request_origin`, `existing_context`, `provider`                        |
| `scan_queued`                 | The queue endpoint accepts the request                                            | `scan_attempt_id`, `queue_latency_ms`, `request_origin`, `existing_context`                |
| `fast_result_ready`           | The enriching view renders a real trust result                                    | `scan_attempt_id`, `time_to_fast_result_ms`, `confidence_band`, `coverage_band`            |
| `complete_context_ready`      | A ready context report renders                                                    | `scan_attempt_id`, `time_to_complete_context_ms`, `fast_result_seen`, `coverage_band`      |
| `evidence_section_viewed`     | An evidence section remains at least 50% visible for one second                   | `section_name`, `section_has_content`                                                      |
| `review_lead_opened`          | A specific ranked review lead disclosure opens                                    | `lead_type`, `lead_position_bucket`, `evidence_tier`, `severity_band`                      |
| `json_or_markdown_downloaded` | A JSON or Markdown artifact link is activated                                     | `artifact_format`, `artifact_variant`, `source_section`                                    |
| `mcp_setup_opened`            | The MCP setup menu transitions from closed to open                                | `mcp_client_default`, `navigation_surface`, `context_available`                            |
| `public_context_shared`       | Copying the public context link succeeds                                          | `share_method`, `share_surface`                                                            |
| `second_repository_scanned`   | A second distinct repository renders a complete context after consent             | `days_since_first_scan_bucket`, `same_session`, `repository_ordinal`                       |
| `feedback_submitted`          | The feedback API accepts the form                                                 | `feedback_category`, `feedback_surface`, `has_repository_context`, `message_length_bucket` |

All custom events also receive `event_schema_version`, `surface`,
`route_template`, `entry_mode`, and `consent_state` from the centralized event
layer.

## Reporting setup

### PostHog

Create these insights:

1. Core ordered funnel, 24-hour conversion window:
   `$pageview → repository_search_started → valid_repository_selected → scan_requested → scan_queued → fast_result_ready → complete_context_ready`
2. Activation funnel:
   `complete_context_ready → evidence_section_viewed → review_lead_opened`
3. Parallel action trends for downloads, MCP setup, and public sharing.
4. Thirty-day retention using `complete_context_ready` as the start and
   `second_repository_scanned` as the return event.

### GA4

In GTM, create a GA4 configuration tag and custom-event triggers for
`page_view` plus every canonical event above. Map same-named data-layer
variables to the GA4 event parameters. Do not enable a second direct Google tag
in application code; GTM is the only browser delivery path to GA4.

Register event-scoped custom dimensions for:

- `surface`, `route_template`, `entry_mode`
- `selection_method`, `request_origin`, `existing_context`
- `coverage_band`, `confidence_band`, `section_name`
- `artifact_format`, `artifact_variant`
- `mcp_client_default`, `navigation_surface`
- `share_method`, `feedback_category`

Register `queue_latency_ms`, `time_to_fast_result_ms`, and
`time_to_complete_context_ms` as custom metrics. Mark `scan_queued` as the
primary key event; `feedback_submitted` may be a secondary key event.

In the GA4 web stream settings, disable enhanced-measurement outbound clicks,
site search, form interactions, file downloads, and browser-history page views.
Those automatic events can collect raw link URLs or duplicate the explicit SPA
events. Keep the explicit `page_view` and canonical custom events as the source
of truth.

## Validation

- Test consent decline, grant, and withdrawal.
- Confirm neither vendor loads before consent.
- Confirm repository routes appear only as `/r/:owner/:repository`.
- Verify each event fires once at its documented trigger.
- Search captured payloads for `repository`, `job_id`, `cve_id`, `commit_sha`,
  artifact URLs, and feedback text.
- Validate PostHog Live Events and GA4 DebugView before production rollout.
