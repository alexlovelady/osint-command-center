// Desktop shell (spec 3.1): starts the loopback backend, learns its ephemeral port and per-launch token through a
// controlled stdout handshake, hands both to the local UI, and stops the backend gracefully on exit.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{Manager, RunEvent, State};

#[derive(Clone, Serialize, Default)]
struct BackendInfo {
    port: u16,
    token: String,
}

#[derive(Default)]
struct Backend {
    child: Mutex<Option<Child>>,
    info: Mutex<Option<BackendInfo>>,
    error: Mutex<Option<String>>,
}

fn project_dir() -> PathBuf {
    if let Ok(d) = std::env::var("OSINTCC_PROJECT_DIR") {
        return PathBuf::from(d);
    }
    // apps/desktop/src-tauri -> repository root (valid for development builds)
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap_or_default()
}

fn python_path(root: &PathBuf) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OSINTCC_PYTHON") {
        return Some(PathBuf::from(p));
    }
    let win = root.join(".venv/Scripts/python.exe");
    let nix = root.join(".venv/bin/python");
    [win, nix].into_iter().find(|p| p.is_file())
}

/// Parses "OSINTCC_READY port=<n> token=<t>". Anything else is ignored (never trusted as instructions).
fn parse_ready(line: &str) -> Option<BackendInfo> {
    let rest = line.strip_prefix("OSINTCC_READY ")?;
    let mut port = None;
    let mut token = None;
    for kv in rest.split_whitespace() {
        match kv.split_once('=') {
            Some(("port", v)) => port = v.parse::<u16>().ok(),
            Some(("token", v)) => token = Some(v.to_string()),
            _ => {}
        }
    }
    match (port, token) {
        (Some(p), Some(t)) if p > 0 && !t.is_empty() => Some(BackendInfo { port: p, token: t }),
        _ => None,
    }
}

/// Packaged layout: the frozen backend sits next to the desktop executable.
fn bundled_backend() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let name = if cfg!(windows) { "osintcc-backend.exe" } else { "osintcc-backend" };
    let p = dir.join(name);
    p.is_file().then_some(p)
}

fn start_backend(state: Arc<Backend>) {
    let mut cmd = if let Some(exe) = bundled_backend() {
        Command::new(exe)
    } else {
        let root = project_dir();
        let Some(python) = python_path(&root) else {
            *state.error.lock().unwrap() = Some(format!(
                "Python environment not found under {}. Run `uv sync` in the project root (or set OSINTCC_PYTHON).",
                root.display()
            ));
            return;
        };
        let mut c = Command::new(python);
        c.args(["-I", "-m", "osintcc.server"]).current_dir(&root); // -I: isolated mode, no user site / cwd imports
        c
    };
    cmd.stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group (so a whole tree can be signalled) and, on Linux, ask the kernel to SIGKILL the backend if this shell
        // dies without cleaning up: the counterpart of the Windows kill-on-close job object.
        cmd.process_group(0);
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            *state.error.lock().unwrap() = Some(format!("Could not start the backend: {e}"));
            return;
        }
    };
    let stdout = child.stdout.take().unwrap();
    *state.child.lock().unwrap() = Some(child);
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(info) = parse_ready(&line) {
                *state.info.lock().unwrap() = Some(info);
                return;
            }
            if Instant::now() > deadline {
                break;
            }
        }
        // Process ended or timed out without the handshake.
        let mut err = state.error.lock().unwrap();
        if state.info.lock().unwrap().is_none() {
            *err = Some("The backend exited before reporting readiness.".into());
        }
    });
}

#[tauri::command]
fn backend_info(state: State<'_, Arc<Backend>>) -> Result<BackendInfo, String> {
    if let Some(i) = state.info.lock().unwrap().clone() {
        return Ok(i);
    }
    if let Some(e) = state.error.lock().unwrap().clone() {
        return Err(format!("failed: {e}"));
    }
    Err("starting".into())
}

/// Ask the backend to stop itself (WAL checkpoint, jobs cancelled), then fall back to killing the process.
fn stop_backend(state: &Backend) {
    if let Some(info) = state.info.lock().unwrap().clone() {
        if let Ok(mut s) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", info.port).parse().unwrap(),
            Duration::from_secs(2),
        ) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let req = format!(
                "POST /api/v1/system/shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                info.token
            );
            let _ = s.write_all(req.as_bytes());
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink);
        }
    }
    if let Some(mut child) = state.child.lock().unwrap().take() {
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Windows: put the shell in a kill-on-close job object. Child processes (the backend) inherit it, so if the shell is
/// killed abruptly the OS terminates the backend too instead of orphaning it.
#[cfg(windows)]
fn bind_children_to_shell() {
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        AssignProcessToJobObject(job, GetCurrentProcess());
        // The handle is intentionally never closed: it is released when the shell process dies.
    }
}

fn main() {
    #[cfg(windows)]
    bind_children_to_shell();
    let backend = Arc::new(Backend::default());
    let for_setup = backend.clone();
    let app = tauri::Builder::default()
        .manage(backend.clone())
        .invoke_handler(tauri::generate_handler![backend_info])
        .setup(move |_app| {
            start_backend(for_setup.clone());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the desktop shell");
    app.run(move |app_handle, event| {
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
            let b = app_handle.state::<Arc<Backend>>();
            stop_backend(&b);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::parse_ready;

    #[test]
    fn parses_valid_handshake() {
        let i = parse_ready("OSINTCC_READY port=51234 token=abc_DEF-123").unwrap();
        assert_eq!((i.port, i.token.as_str()), (51234, "abc_DEF-123"));
    }

    #[test]
    fn rejects_noise_and_bad_values() {
        for l in ["", "hello", "OSINTCC_READY", "OSINTCC_READY port=0 token=x", "OSINTCC_READY port=99999 token=x",
                  "OSINTCC_READY port=80", "OSINTCC_READY token=x", "  OSINTCC_READY port=80 token=x"] {
            assert!(parse_ready(l).is_none(), "{l:?}");
        }
    }
}
