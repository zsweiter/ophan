## 1. Middleware Execution Blueprint

Notice how **both** middleware rejections and upstream networking failures collapse into the exact same `error_handler` box, which then funnels straight into `prepare_response` and `terminate_response`.

```text
[CLIENT] ── HTTP Request ──► │ PROXY: init_session(session)
                             │
                             ▼
                    ╔════════════════════════════════════════════════════════╗
                    ║ MIDDLEWARE: on_request(&req, &mut ctx)                 ║
                    ╚════════════════════════════════════════════════════════╝
                             │
          ┌──────────────────┼──────────────────────────────┐
     [Continue]          [Respond]                      [Reject]
          │                  │                              │
          ▼                  ▼                              │
┌──────────────────┐ ┌───────────────────────────┐          │
│ PROXY: Routing   │ │ PROXY: Shortcut Response  │          │
│ (Lookup Route)   │ │ (e.g., CORS Preflight)    │          │
└────────┬─────────┘ └───────────┬───────────────┘          │
         │                       │                          │
   ┌─────┴──────┐                │                          │
[Upstream]   [Static]            │                          │
   │            │                │                          │
   ▼            ▼                │                          │
╔════════════╗ ┌────────────────┐│                          │
║ MIDDLEWARE ║ │ PROXY:         ││                          │
║ on_upstream│ │ File Server    ││                          │
║ _request   ║ │ reads local    ││                          │
╚════════════╝ │ disk file      ││                          │
   │           └────────┬───────┘│                          │
   ▼                    │        │                          │
┌────────────┐          │        │                          │
│ PROXY:     │          │        │                          │
│ Connect &  │          │        │                          │
│ Transmit   │          │        │                          │
└────┬───────┘          │        │                          │
     │                  │        │                          │
 [Net Error?]           │        │                          │
   ├── Yes ─────────────┼────────┼──────────────────────────┼────────┐
   └── No ──┐           │        │                          │        │
            ▼           │        │                          │        │
╔════════════╗          │        │                          │        │
║ MIDDLEWARE ║          │        │                          │        │
║ on_upstream│          │        │                          │        │
║ _response  ║          │        │                          │        │
╚════════════╝          │        │                          │        │
     │                  │        │                          │        │
     ▼                  │        │                          │        │
┌────────────┐          │        │                          │        │
│ Pingora    │          │        │                          │        │
│ streams    │          │        │                          │        │
│ body to    │          │        │                          │        │
│ Client     │          │        │                          │        │
└────┬───────┘          │        │                          │        │
     │                  ▼        ▼                          ▼        ▼
     │              ╔════════════════════════════════════════════════════════╗
     │              ║ MIDDLEWARE: prepare_response(&ctx, &mut resp)          ║
     │              ╚════════════════════════════════════════════════════════╗
     │                       │                                       ▲
     │                       ▼                                       │
     │              ┌───────────────────────────────────────────┐    │
     │              │ PROXY: terminate_response(session, resp)  │    │
     │              └───────────────────────────────────────────┘    │
     │                                                               │
     ▼                                                               │
┌────────────────────────────────────────────────────────────────────┼───────┐
│ PROXY: error_handler(session, ctx, error) ─────────────────────────┘       │
│ ──► Catch-all for Rejects, File Server misses, and Upstream Net Errors     │
└────────────────────────────────────────────────────────────────────────────┘

```

---

## 2. Refined Hook Signatures & Params

### Middleware Hooks (Negocio / Domain Layer)

```rust
pub trait OphanMiddleware: Send + Sync {
    /// 1. Inbound Request Phase
    fn on_request(
        &self, 
        ctx: &mut Context, 
        req: &mut RequestHeader
    ) -> Result<FlowDecision, InternalError>;

    /// 2. Upstream Request Phase
    /// Added `session` to allow middlewares to read transport-level metadata 
    /// or connection context before rewriting upstream payloads.
    fn on_upstream_request(
        &self, 
        session: &mut PingoraSession,
        ctx: &mut Context, 
        upstream_req: &mut RequestHeader
    ) -> Result<(), InternalError>;

    /// 3. Upstream Response Phase
    /// Added `session` so downstream connection states can be cross-referenced 
    /// when auditing or parsing headers returned by the remote backend.
    fn on_upstream_response(
        &self, 
        session: &mut PingoraSession,
        ctx: &mut Context, 
        upstream_resp: &mut ResponseHeader
    ) -> Result<(), InternalError>;

    /// 4. Outbound Compliance Phase
    fn prepare_response(
        &self, 
        ctx: &Context, 
        resp: &mut ResponseHeader
    ) -> Result<(), InternalError>;
}

```

### Proxy Engine Hooks (Infrastructure / Network Layer)

* **`init_session(session: &mut PingoraSession) -> Context`**
* *Purpose:* Allocates the initial transaction context.


* **`error_handler(session: &mut PingoraSession, ctx: &mut OphanContext, error: OphanError) -> ResponseHeader`**
* *Purpose:* The single, unified fallback generator. It maps any failure—whether it's a middleware `Reject`, a static file missing on disk, or a severe network drop caught inside Pingora's `fail_to_proxy`—into a clean HTTP error metadata structure. This structure is immediately forwarded to `prepare_response`.


* **`terminate_response(session: &mut PingoraSession, resp: ResponseHeader, body: Option<BodyBytes>)`**
* *Purpose:* Directly writes the finalized memory buffers down to the client socket and drops the connection loop for Static, Shortcut, and Error pathways.