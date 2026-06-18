use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for_port(host: &str, port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&format!("{host}:{port}").parse().unwrap(), Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn http_get(host: &str, port: u16, path: &str, host_header: &str) -> String {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).expect("connect to gateway");

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    buf
}

#[test]
fn e2e_gateway_serves_requests() {
    // ── 1. Mock upstream ─────────────────────────────────────
    let mock_server = httpmock::MockServer::start();
    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/v1");
        then.status(200).body("from-mock");
    });

    // ── 2. Write config ──────────────────────────────────────
    let tmp = tempfile::tempdir().expect("create temp dir");
    let cfg_dir = tmp.path().join("config");
    let gw_dir = cfg_dir.join("gateways");
    std::fs::create_dir_all(&gw_dir).unwrap();

    let mock_port = mock_server.port();

    let master = format!(
        r#"master "test" {{
    user = "nobody"
    workers = "auto"
    pid = "/tmp/ophan-test.pid"
    error_log = "/tmp/ophan-test.log"
    includes = "{gw}/test.conf"
}}
"#,
        gw = gw_dir.display()
    );
    std::fs::write(cfg_dir.join("master.conf"), &master).unwrap();

    let gw_cfg = format!(
        r#"name = "test-gw"
listeners {{ listener "main" {{ address = "127.0.0.1:5050" }} }}
upstreams {{ upstream "api" {{ servers = "127.0.0.1:{mp}" }} }}
routes {{
    route "/*" {{
        hosts = ["api.example.me"]
        backend = upstream("api")
    }}
}}
"#,
        mp = mock_port
    );
    std::fs::write(gw_dir.join("test.conf"), &gw_cfg).unwrap();

    // ── 3. Start gateway ─────────────────────────────────────
    let binary = {
        let mut p = std::env::current_exe().unwrap();
        for _ in 0..2 {
            p.pop();
        }
        p.join("ophan")
    };
    assert!(binary.exists(), "Binary not found. Build with `cargo build` first.");

    let mut child = Command::new(&binary)
        .env("CONFIG_PATH", cfg_dir.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ophan");

    let child_stderr = child.stderr.take().unwrap();

    // ── 4. Wait and test ────────────────────────────────────
    let ready = wait_for_port("127.0.0.1", 5050, Duration::from_secs(10));
    assert!(ready, "gateway did not start");

    let response = http_get("127.0.0.1", 5050, "/v1", "api.example.me");

    let _ = child.kill();
    let _ = child.wait();

    // Read stderr
    let mut stderr_buf = String::new();
    std::io::BufReader::new(child_stderr).read_to_string(&mut stderr_buf).ok();
    if !stderr_buf.is_empty() {
        eprintln!("[test] === Gateway stderr ===\n{}", stderr_buf);
    }

    eprintln!(
        "[test] Full response status line:\n{}",
        response.lines().next().unwrap_or("(empty)")
    );

    assert!(
        response.contains("200 OK"),
        "Expected 200, got:\n{}",
        response.lines().next().unwrap_or("(empty)")
    );
    assert_eq!(mock.calls(), 1, "mock should have received 1 request");
}
