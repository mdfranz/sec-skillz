# Amazon CloudFront Log Format Reference

## Format Overview
- **Standard Logs (Access Logs)**: Delivered to S3 as `.gz` files. Tab-separated values (TSV) with two header lines.
- **Real-time Logs**: Delivered to Kinesis Data Streams. Highly configurable, JSON-compatible if configured.
- **Key Fields (Standard Logs)**:
    - `date` & `time`: When the request was completed.
    - `x-edge-location`: The edge location that served the request.
    - `sc-bytes`: Total bytes sent by the server to the client.
    - `c-ip`: Client IP address.
    - `cs-method`: HTTP request method.
    - `cs-host`: The domain name of the CloudFront distribution.
    - `cs-uri-stem`: The URI path.
    - `sc-status`: HTTP status code.
    - `cs-referer`: The Referer header.
    - `cs-user-agent`: The User-Agent header.
    - `cs-uri-query`: The query string.
    - `x-edge-result-type`: How the edge responded (e.g., `Hit`, `Miss`, `Error`, `LimitExceeded`).
    - `x-edge-request-id`: Unique ID for the request.
    - `x-host-header`: The Host header sent by the client.
    - `cs-protocol`: The protocol (http, https, ws, wss).
    - `cs-bytes`: Total bytes received from the client.
    - `time-taken`: Seconds from request to response.

## Log Header Structure
CloudFront standard logs start with:
```text
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs-host cs-uri-stem sc-status cs-referer cs-user-agent cs-uri-query cs-cookie x-edge-result-type x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status fle-encrypt-id c-port time-to-first-byte x-edge-detailed-result-type sc-content-type sc-content-len sc-range-start sc-range-end
```

## Result Types for Security Hunting
- **`LimitExceeded`**: Often indicates a WAF rate-limit rule was triggered.
- **`Error`**: The request was blocked (e.g., WAF, Geoblocking) or the origin failed.
- **`CapacityExceeded`**: May indicate a DDoS or overwhelming volume.
- **`Redirect`**: Request was redirected at the edge (e.g., HTTP to HTTPS).

## Common User-Agent Patterns
- **Bots/Scrapers**: Often have `User-Agent` strings like `python-requests`, `Go-http-client`, or custom strings like `headless-chrome`.
- **Empty User-Agent**: Frequently associated with basic automated scripts.
