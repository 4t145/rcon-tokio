//! # Tokio Rcon Protocol implementation
//!
//! Reference: https://developer.valvesoftware.com/wiki/Source_RCON_Protocol

use std::{
    collections::HashMap,
    pin::{self},
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use packet::{
    DecodeError, EncodeError, MARGIN, MAX_PACKET_SIZE, RconPacket, RconPacketCodec,
    SERVERDATA_AUTH_RESPONSE, SERVERDATA_RESPONSE_VALUE,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::{
    codec::Framed,
    sync::{CancellationToken, DropGuard},
};
pub mod packet;

struct ClientService {
    request_rx: tokio::sync::mpsc::Receiver<Request>,
    ct: CancellationToken,
}

struct Request {
    kind: RequestKind,
    responder: tokio::sync::oneshot::Sender<Response>,
}

enum RequestKind {
    ExecCommand { command: Bytes },
}
enum Response {
    Response(Bytes),
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Empty body")]
    EmptyBody,
    #[error("Body too large")]
    BodyTooLarge,
    #[error("Connection closed")]
    ConnectionClosed,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientServiceError {
    #[error("Encode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("Decode error: {0}")]
    Encode(#[from] EncodeError),
    #[error("Fail to auth")]
    AuthFail,
}

#[derive(Debug)]
pub enum ExitReason {
    Error(ClientServiceError),
    Cancelled,
    StreamTerminated,
}

pub struct Client {
    request_tx: tokio::sync::mpsc::Sender<Request>,
}

impl Client {
    pub async fn command(&self, command: impl Into<Bytes>) -> Result<Bytes, ClientError> {
        let command = command.into();
        if command.len() + MARGIN > MAX_PACKET_SIZE {
            return Err(ClientError::BodyTooLarge);
        } else if command.is_empty() {
            return Err(ClientError::EmptyBody);
        };
        let (responder, receiver) = tokio::sync::oneshot::channel();
        self.request_tx
            .send(Request {
                kind: RequestKind::ExecCommand { command },
                responder,
            })
            .await
            .map_err(|_| ClientError::ConnectionClosed)?;
        let response = receiver.await.map_err(|_| ClientError::ConnectionClosed)?;
        match response {
            Response::Response(bytes) => Ok(bytes),
        }
    }
}

pub struct ClientServiceHandle {
    request_tx: tokio::sync::mpsc::Sender<Request>,
    join_handle: tokio::task::JoinHandle<ExitReason>,
    _guard: DropGuard,
}

impl ClientServiceHandle {
    pub fn initialize_whitout_auth<S>(
        stream: S,
        ct: CancellationToken,
    ) -> ClientServiceHandle
    where
        S: AsyncWrite + AsyncRead + Send + 'static,
    {
        let guard = ct.clone().drop_guard();
        let stream = Framed::new(stream, RconPacketCodec);
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(16);
        let service = ClientService { request_rx, ct };
        let join_handle = tokio::task::spawn(service.run(stream));
        ClientServiceHandle {
            request_tx,
            join_handle,
            _guard: guard,
        }
    }
    pub async fn initialize<S>(
        stream: S,
        password: Option<Bytes>,
        ct: CancellationToken,
    ) -> Result<ClientServiceHandle, ClientServiceError>
    where
        S: AsyncWrite + AsyncRead + Unpin + Send + 'static,
    {
        let guard = ct.clone().drop_guard();
        let mut stream = Framed::new(stream, RconPacketCodec);
        const ID: i32 = 0;
        if let Some(auth) = password {
            stream.send(RconPacket::auth(ID, auth)).await?;
            let auth_result = stream.next().await.ok_or(ClientServiceError::AuthFail)??;
            tracing::debug!(?auth_result, "auth result");
            if auth_result.ty != SERVERDATA_AUTH_RESPONSE || auth_result.id != ID {
                return Err(ClientServiceError::AuthFail);
            }
        }
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(16);
        let service = ClientService { request_rx, ct };
        let join_handle = tokio::task::spawn(service.run(stream));
        Ok(ClientServiceHandle {
            request_tx,
            join_handle,
            _guard: guard,
        })
    }

    pub fn client(&self) -> Client {
        Client {
            request_tx: self.request_tx.clone(),
        }
    }

    pub async fn wait(self) -> Result<ExitReason, tokio::task::JoinError> {
        self.join_handle.await
    }

    pub async fn cancel(self) -> Result<(), tokio::task::JoinError> {
        self._guard.disarm().cancel();
        self.join_handle.await?;
        Ok(())
    }
}

impl ClientService {
    pub async fn run<S>(mut self, mut stream: Framed<S, RconPacketCodec>) -> ExitReason
    where
        S: AsyncWrite + AsyncRead,
    {
        let mut client_id: i32 = 1;
        let mut responders: HashMap<i32, tokio::sync::oneshot::Sender<Response>> = HashMap::new();
        enum Event {
            Request(Request),
            Response(RconPacket),
            Error(ClientServiceError),
        }
        let mut stream = pin::pin!(stream);
        let reason = loop {
            let next_event = tokio::select! {
                _ = self.ct.cancelled() => {
                    break ExitReason::Cancelled;
                }
                response = stream.next() => {
                    match response {
                        Some(Ok(packet)) => {
                            Event::Response(packet)
                        },
                        Some(Err(e)) => {
                            Event::Error(e.into())
                        },
                        None => {
                            break ExitReason::StreamTerminated
                        },
                    }
                }
                request = self.request_rx.recv() => {
                    match request {
                        Some(req) =>
                        {
                            Event::Request(req)
                        },
                        None => {
                            continue
                        },
                    }
                }
            };
            match next_event {
                Event::Request(request) => {
                    let Request { kind, responder } = request;
                    client_id = client_id.wrapping_add(1);
                    responders.insert(client_id, responder);

                    match kind {
                        RequestKind::ExecCommand { command } => {
                            if let Err(e) =
                                stream.send(RconPacket::command(client_id, command)).await
                            {
                                return ExitReason::Error(e.into());
                            }
                        }
                    }
                }
                Event::Response(rcon_packet) => {
                    if rcon_packet.ty == SERVERDATA_RESPONSE_VALUE {
                        if let Some(responder) = responders.remove(&rcon_packet.id) {
                            let _ = responder.send(Response::Response(rcon_packet.body));
                        }
                    }
                }
                Event::Error(client_error) => break ExitReason::Error(client_error),
            }
        };
        tracing::debug!(?reason, "rcon connection exit");
        reason
    }
}
