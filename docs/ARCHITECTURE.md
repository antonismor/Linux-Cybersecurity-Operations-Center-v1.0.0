# Architecture

## Linux Cybersecurity Operations Center v1.0.0

The controller is designed around a small set of independently replaceable layers:

~~~text
Endpoint Agents
      |
      | HTTPS
      v
Nginx TLS Gateway
      |
      v
FastAPI Controller
      |
      +---- PostgreSQL
      +---- WebSocket Hub
      +---- Download Repository
~~~

## Controller

The controller runs on Debian 13 and binds the FastAPI process to 127.0.0.1:8010. Nginx exposes the HTTPS interface on TCP/8443.

## Database

PostgreSQL stores endpoints, event metadata, incidents, and enrollment-token state.

Persistent endpoint tokens are stored server-side as SHA-256 hashes rather than plaintext.

## Enrollment

An administrator creates a one-time enrollment token. The endpoint exchanges it for a unique persistent endpoint credential. The enrollment token is then marked used.

## Live UI

The browser uses the REST API for state and a WebSocket for near-real-time refresh notifications.

## Agent model

The Go desktop agent is a cross-platform baseline that provides endpoint identity, heartbeat, process snapshots, and network snapshots.

Platform-specific sensors can later extend this architecture without changing the enrollment and transport model.

## Mobile

Android and iOS have different platform security models. The controller exposes deployment packages/templates without claiming unsupported desktop-equivalent privileges.

**Powered and Development by antonios.mortos@outlook.com**
