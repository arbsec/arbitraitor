//! Cargo-built mock subprocess plugin for executor integration tests.

#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    loop {
        let Some(frame) = read_frame()? else {
            return Ok(());
        };
        if frame.contains("HelloRequest") {
            write_frame(&hello_response())?;
        } else if frame.contains("InitRequest") {
            write_frame(r#"{"version":1,"kind":"InitResponse","payload":{}}"#)?;
        } else if frame.contains("AnalyzeRequest") {
            write_frame(r#"{"version":1,"kind":"AnalyzeResponse","payload":{"findings":[]}}"#)?;
        } else if frame.contains("LookupRequest") {
            std::thread::sleep(std::time::Duration::from_mins(1));
        } else if frame.contains("ShutdownRequest") {
            return Ok(());
        } else {
            write_frame(
                r#"{"version":1,"kind":"ErrorResponse","payload":{"reason":"unknown request"}}"#,
            )?;
        }
    }
}

fn read_frame() -> io::Result<Option<String>> {
    let mut prefix = [0_u8; 4];
    match io::stdin().read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(prefix);
    let mut payload = vec![0_u8; usize::try_from(length).unwrap_or_default()];
    io::stdin().read_exact(&mut payload)?;
    Ok(Some(String::from_utf8_lossy(&payload).into_owned()))
}

fn write_frame(payload: &str) -> io::Result<()> {
    let bytes = payload.as_bytes();
    let length = u32::try_from(bytes.len()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame too large: {error}"),
        )
    })?;
    io::stdout().write_all(&length.to_be_bytes())?;
    io::stdout().write_all(bytes)?;
    io::stdout().flush()
}

fn hello_response() -> String {
    let value = env::var("PATH").unwrap_or_else(|_| "<missing>".to_owned());
    format!(
        r#"{{"version":1,"kind":"HelloResponse","payload":{{"identity":{{"id":"plugin.test.mock","version":"1.0.0","trust_class":"first-party"}},"capabilities":{{"network":"none","filesystem":"none","process":"none","max_memory_bytes":null,"max_cpu_ms":null}},"plugin_type":"detector","description":"env:{value}"}}}}"#
    )
}
