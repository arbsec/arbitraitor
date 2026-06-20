//! Running subprocess plugin lifecycle management.

#![forbid(unsafe_code)]

use std::process::{Child, ChildStdin};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use arbitraitor_plugin_api::PluginManifest;
use serde_json::{Value, json};

use super::ExecutorError;
use super::message::{expected_response_kind, placeholder_manifest};
use super::process::kill_child_group;
use crate::error::ProtocolError;
use crate::frame::FrameWriter;
use crate::protocol::{MessageKind, ProtocolMessage};

/// Running subprocess plugin instance.
pub struct SubprocessPlugin {
    process: Option<Child>,
    frame_writer: FrameWriter<ChildStdin>,
    responses: Receiver<Result<ProtocolMessage, ProtocolError>>,
    reader_thread: Option<thread::JoinHandle<()>>,
    manifest: PluginManifest,
    timeout: Duration,
}

impl SubprocessPlugin {
    pub(super) fn new(
        child: Child,
        stdin: ChildStdin,
        responses: Receiver<Result<ProtocolMessage, ProtocolError>>,
        reader_thread: thread::JoinHandle<()>,
        timeout: Duration,
    ) -> Self {
        Self {
            process: Some(child),
            frame_writer: FrameWriter::new(stdin),
            responses,
            reader_thread: Some(reader_thread),
            manifest: placeholder_manifest(),
            timeout,
        }
    }

    /// Sends a hello request and records the plugin manifest from the response.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] if the plugin exits, times out, returns a
    /// non-hello response, or sends a malformed manifest payload.
    pub fn handshake(&mut self) -> Result<PluginManifest, ExecutorError> {
        self.send(MessageKind::HelloRequest, json!({}))?;
        let response = self.receive(self.timeout)?;
        if response.kind != MessageKind::HelloResponse {
            return Err(ExecutorError::Handshake(format!(
                "expected HelloResponse, got {:?}",
                response.kind
            )));
        }
        let manifest: PluginManifest = serde_json::from_value(response.payload)
            .map_err(|error| ExecutorError::Handshake(error.to_string()))?;
        self.manifest = manifest.clone();
        Ok(manifest)
    }

    /// Sends plugin configuration and waits for initialization acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the plugin exits, times out, or returns a
    /// response other than [`MessageKind::InitResponse`].
    pub fn init(&mut self, config: Value) -> Result<(), ExecutorError> {
        self.send(MessageKind::InitRequest, config)?;
        self.expect_response(MessageKind::InitResponse)
            .map(|_payload| ())
    }

    /// Sends an operation request and waits for a response with the executor timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the plugin exits, times out, returns a
    /// protocol error, or sends an error response.
    pub async fn request(
        &mut self,
        kind: MessageKind,
        payload: Value,
    ) -> Result<Value, ExecutorError> {
        tokio::task::yield_now().await;
        let expected = expected_response_kind(kind).ok_or_else(|| {
            ExecutorError::Handshake(format!("unsupported request kind: {kind:?}"))
        })?;
        self.send(kind, payload)?;
        self.expect_response(expected)
    }

    /// Sends shutdown and waits for the process to exit.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the process cannot be signalled or does
    /// not exit before the configured timeout.
    pub fn shutdown(&mut self) -> Result<(), ExecutorError> {
        self.send(MessageKind::ShutdownRequest, json!({}))?;
        self.wait_for_exit(self.timeout)
    }

    /// Returns the operating-system process identifier while the plugin is running.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.process.as_ref().map(Child::id)
    }

    fn send(&mut self, kind: MessageKind, payload: Value) -> Result<(), ExecutorError> {
        let message = ProtocolMessage::new(kind, payload);
        self.frame_writer.write_frame(&message)?;
        Ok(())
    }

    fn expect_response(&mut self, expected: MessageKind) -> Result<Value, ExecutorError> {
        let response = self.receive(self.timeout)?;
        if response.kind == MessageKind::ErrorResponse {
            return Err(ExecutorError::Handshake(response.payload.to_string()));
        }
        if response.kind != expected {
            return Err(ExecutorError::Handshake(format!(
                "expected {expected:?}, got {:?}",
                response.kind
            )));
        }
        Ok(response.payload)
    }

    fn receive(&mut self, timeout: Duration) -> Result<ProtocolMessage, ExecutorError> {
        match self.exit_state()? {
            ProcessExit::Running => {}
            ProcessExit::Exited(code) | ProcessExit::Gone(code) => {
                return Err(ExecutorError::UnexpectedExit(code));
            }
        }
        match self.responses.recv_timeout(timeout) {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(ExecutorError::Protocol(error)),
            Err(RecvTimeoutError::Timeout) => Err(ExecutorError::Timeout(timeout)),
            Err(RecvTimeoutError::Disconnected) => match self.exit_state()? {
                ProcessExit::Running => Err(ExecutorError::UnexpectedExit(None)),
                ProcessExit::Exited(code) | ProcessExit::Gone(code) => {
                    Err(ExecutorError::UnexpectedExit(code))
                }
            },
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<(), ExecutorError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(child) = &mut self.process {
                if child.try_wait()?.is_some() {
                    self.process = None;
                    self.join_reader();
                    return Ok(());
                }
            } else {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.kill_tree();
                return Err(ExecutorError::Timeout(timeout));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn exit_state(&mut self) -> Result<ProcessExit, ExecutorError> {
        let Some(child) = &mut self.process else {
            return Ok(ProcessExit::Gone(None));
        };
        match child.try_wait()? {
            Some(status) => {
                let code = status.code();
                self.process = None;
                self.join_reader();
                Ok(ProcessExit::Exited(code))
            }
            None => Ok(ProcessExit::Running),
        }
    }

    fn kill_tree(&mut self) {
        if let Some(mut child) = self.process.take() {
            kill_child_group(&child);
            let _kill_result = child.kill();
            let _wait_result = child.wait();
        }
        self.join_reader();
    }

    fn join_reader(&mut self) {
        if let Some(handle) = self.reader_thread.take() {
            let _join_result = handle.join();
        }
    }
}

impl Drop for SubprocessPlugin {
    fn drop(&mut self) {
        self.kill_tree();
    }
}

enum ProcessExit {
    Running,
    Exited(Option<i32>),
    Gone(Option<i32>),
}
