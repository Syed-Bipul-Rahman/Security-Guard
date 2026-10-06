//! A tiny HTTP/1.0 server for collectors, IP lookups, the advisory API and the
//! OTA update channel. One thread per connection, `Connection: close`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type Headers = BTreeMap<String, String>;
type Reply = (u16, Vec<(String, String)>, Vec<u8>);

#[derive(Default)]
struct State {
    routes: BTreeMap<String, Reply>,
    posts: Vec<(String, Headers, Vec<u8>)>,
    gets: Vec<(String, Headers)>,
    dir: Option<PathBuf>,
}

/// Routes are keyed "PATH" for GET (with the query string) or "POST PATH".
/// Unrouted GETs are served from `dir` when set, else 404; unrouted POSTs get
/// 200 "ok". Header names in the recorded requests are lower-cased.
#[derive(Clone)]
pub struct Server {
    pub url: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    pub fn new() -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let state = Arc::new(Mutex::new(State::default()));
        let st = state.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let st = st.clone();
                std::thread::spawn(move || {
                    let _ = handle(c, &st);
                });
            }
        });
        Server { url, state }
    }
    /// Serves files under `dir`, as http.server.SimpleHTTPRequestHandler did.
    pub fn serve_dir(dir: PathBuf) -> Server {
        let s = Server::new();
        s.state.lock().unwrap().dir = Some(dir);
        s
    }
    pub fn route(&self, key: &str, status: u16, headers: &[(&str, &str)], body: impl AsRef<[u8]>) {
        let h = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.state
            .lock()
            .unwrap()
            .routes
            .insert(key.into(), (status, h, body.as_ref().to_vec()));
    }
    pub fn posts(&self) -> Vec<(String, Headers, Vec<u8>)> {
        self.state.lock().unwrap().posts.clone()
    }
    pub fn gets(&self) -> Vec<(String, Headers)> {
        self.state.lock().unwrap().gets.clone()
    }
    pub fn clear(&self) {
        let mut s = self.state.lock().unwrap();
        s.posts.clear();
        s.gets.clear();
    }
}

fn handle(c: TcpStream, st: &Mutex<State>) -> std::io::Result<()> {
    let mut r = BufReader::new(c.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("/").to_string(),
    );
    let mut headers = Headers::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let (status, rh, body) = if method == "POST" {
        let n: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; n];
        r.read_exact(&mut body)?;
        let mut s = st.lock().unwrap();
        s.posts.push((path.clone(), headers, body));
        s.routes
            .get(&format!("POST {path}"))
            .cloned()
            .unwrap_or((200, vec![], b"ok".to_vec()))
    } else {
        let mut s = st.lock().unwrap();
        s.gets.push((path.clone(), headers));
        match s.routes.get(&path).cloned() {
            Some(r) => r,
            None => {
                let file = s
                    .dir
                    .as_ref()
                    .map(|d| d.join(path.split('?').next().unwrap().trim_start_matches('/')));
                match file.and_then(|f| std::fs::read(f).ok()) {
                    Some(b) => (200, vec![], b),
                    None => (404, vec![], b"not found".to_vec()),
                }
            }
        }
    };
    let mut w = c;
    let mut head = format!("HTTP/1.0 {status} X\r\n");
    for (k, v) in &rh {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    w.write_all(head.as_bytes())?;
    w.write_all(&body)?;
    w.flush()
}
