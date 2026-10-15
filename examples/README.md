# Examples

| Directory | What it shows |
| --- | --- |
| [quickstart](quickstart/) | `caparra-gate` in front of a local file server on the fake rail: one exact-scope route at 21 sat, payable with L402 or `payment:lightning/charge`, and `setup.sh`, which writes the keys and signs the manifest. The run is in the README's Quickstart. For local testing only. |
| [llm-proxy](llm-proxy/) | `caparra-gate` in front of an OpenAI-compatible endpoint: a metered `chat` route paid with `bnap:notes` (route-scope offers, 500 sat per 1,000 tokens up to 2,100 sat per call, a 20% discount for registered DPoP keys), and exact-scope L402 and `payment:lightning/charge` offers at the ceiling for clients with no BNAP code. Also the Caddy `forward_auth` and nginx `auth_request` fronts. |
