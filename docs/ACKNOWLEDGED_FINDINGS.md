# Acknowledged findings

## Purpose

Acknowledgement is for a known active condition that the operator accepts temporarily or indefinitely, such as intentionally leaving SSH password authentication enabled.

It is not a dismissal of the finding. The finding remains active, retains its severity, and continues to contribute to the posture score.

## User experience

Every active finding includes an **Acknowledge and mute** switch.

When enabled:

- the finding appears in the Acknowledged Findings card above Recent Security Events
- its original details remain available
- the actor and acknowledgement time are shown
- repeated security timeline entries for that fingerprint are suppressed
- ntfy alert and recovery notifications for that fingerprint are suppressed

Selecting **Resume alerts** reverses the mute. If the finding remains active, it is eligible for notification on the next collector evaluation.

## Lifecycle behavior

| Transition | Result |
| --- | --- |
| Active to acknowledged | One acknowledgement event is recorded. |
| Acknowledged and unchanged | No repeated event or push notification is created. |
| Acknowledged severity change | One severity-change event is recorded. Push remains muted. |
| Acknowledged to resolved | One resolution event is recorded and acknowledgement is cleared. |
| Resolved finding recurs | The recurrence is unacknowledged and alerts normally. |
| Resume alerts while active | One resume event is recorded and normal alert evaluation resumes. |

## Persistence

Acknowledgements are stored in:

```text
/var/lib/edgewatch/control/edgewatch-control.db
```

The web service can write only to the control directory. It remains read-only to the collector history database and the live snapshot.

## Identity and request protection

The acknowledgement endpoint accepts only authenticated requests delivered through Caddy and oauth2-proxy. It requires:

- a trusted `X-Auth-Request-*` identity header
- the expected HTTPS Origin host
- JSON content type
- the EdgeWatch action header
- a bounded request body
- an exact fingerprint from the current active snapshot before acknowledgement

Caddy must remove client-supplied identity headers before oauth2-proxy repopulates them.
