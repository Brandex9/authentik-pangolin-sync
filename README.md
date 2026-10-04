# Authentik to Pangolin Dynamic IP Whitelist Synchronizer

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Layer: Zero Trust Edge](https://img.shields.io/badge/Security-Zero--Trust%20ZTNA-green.svg)](#)

A zero-dependency Python microservice that listens to Authentik event webhooks, reliably resolves originating client public WAN IPs through multi-tier reverse proxies, and dynamically registers temporary IP exemptions on Pangolin proxy endpoints.

---

## The Problem Statement

Securing self-hosted media and synchronization platforms (e.g., Jellyfin, Immich) behind Identity Provider (IdP) forward-authentication creates an operational deadlock for consumer client applications:

1. **Redirect Failures:** Native smart TV apps (Roku, Apple TV, Google TV) cannot execute browser-based OIDC/SAML redirection chains.
2. **Dynamic Residential IPs:** Remote family members and mobile devices possess changing residential WAN IPs, making static firewall whitelisting unviable.
3. **Overly Permissive Ingress:** Exposing streaming endpoints directly to the public internet invites credential stuffing and zero-day exploit probes.

---

## Architectural Workflow

```text
                 [ User / Smart TV ]
                         │
                         ▼ (1. Authenticates via browser on Mobile / WebAuthn)
┌────────────────────────────────────────────────────────┐
│ Authentik Identity Provider (VLAN 10: App Core)        │
│ • Validates MFA / FIDO2 Token                          │
│ • Fires Webhook with HTTP Context Payload              │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼ (2. HTTP POST with Context Headers)
┌────────────────────────────────────────────────────────┐
│ authentik-pangolin-sync Microservice                   │
│ • Validates X-Authentik-Secret                         │
│ • Extracts CF-Connecting-IP / X-Real-IP                │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼ (3. Authorized Ingress REST Call)
┌────────────────────────────────────────────────────────┐
│ Pangolin Reverse Proxy (VLAN 30: DMZ Media)           │
│ • Injects Client IP into Dynamic Whitelist Table       │
│ • Sets 24-Hour TTL Expiration Window                   │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼ (4. Direct Streaming Permitted)
[ Smart TV Jellyfin Client Streams Without VPN Client ]
```

---

## Configuration & Environment Variables

| Variable                   | Description                                            | Default                          |
| :------------------------- | :----------------------------------------------------- | :------------------------------- |
| `LISTEN_HOST`              | Network interface to bind the webhook server           | `0.0.0.0`                        |
| `LISTEN_PORT`              | Port for the webhook receiver                          | `9190`                           |
| `AUTHENTIK_WEBHOOK_SECRET` | Pre-shared key validated against `X-Authentik-Secret`  | _Required_                       |
| `PANGOLIN_API_URL`         | Base API URL of your Pangolin instance                 | `http://10.30.30.30:8080/api/v1` |
| `PANGOLIN_API_KEY`         | Scoped API token with whitelist read/write permissions | _Required_                       |
| `PANGOLIN_SERVICE_ID`      | Identifier of the Pangolin service target              | `jellyfin-core`                  |
| `RULE_TTL_SECONDS`         | Lease duration in seconds before the whitelist expires | `86400` (24h)                    |

---

## Authentik Notification Rule Setup

1. In Authentik Admin, navigate to **Events $\rightarrow$ Notification Transports**.
2. Create a **Webhook Transport**:
   - **URL:** `http://10.10.10.25:9190/` (IP of this microservice)
   - **Header:** `X-Authentik-Secret: <YOUR_SECRET>`
3. Navigate to **Events $\rightarrow$ Rules** and create an Event Rule targeting `authentik.events.login`.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
