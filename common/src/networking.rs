use anyhow::Result;
pub use libp2p::Multiaddr;
use libp2p::{
    futures::StreamExt, gossipsub::{
        self, Behaviour as GossipsubBehaviour, Event as GossipsubEvent,
        MessageAuthenticity,
    }, identity::Keypair, mdns, request_response::{
        Behaviour as ReqRespBehaviour, Config as ReqRespConfig, Event as ReqRespEvent,
        Message as ReqRespMessage, ProtocolSupport, ResponseChannel,
    }, swarm::{dial_opts::DialOpts, ConnectionId, DialError, NetworkBehaviour, SwarmEvent}, PeerId, Swarm
};
use rand::random;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use tokio::{
    select,
    sync::{broadcast, mpsc},
};

use crate::{
    message::NetworkingMessage,
    networking::reqresp::{DM_PROTO, DMCodec, DMRequest, DMResponse},
};

mod reqresp;

#[derive(Clone, Debug)]
pub struct Outbound {
    pub to: Option<PeerId>,
    pub reference: Option<Reference>,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

impl Outbound {
    pub fn from_message_and_topics(
        topics: Vec<String>,
        message: NetworkingMessage,
    ) -> anyhow::Result<Self> {
        let encoded = bincode::serialize(&message)?;
        Ok(Self {
            reference: None,
            to: None,
            topics,
            data: encoded,
        })
    }

    pub fn direct(to: PeerId, message: NetworkingMessage) -> anyhow::Result<Self> {
        let encoded = bincode::serialize(&message)?;
        Ok(Self {
            to: Some(to),
            topics: Vec::new(),
            data: encoded,
            reference: None,
        })
    }

    pub fn direct_response(
        message: NetworkingMessage,
        reference: Reference,
    ) -> anyhow::Result<Self> {
        let encoded = bincode::serialize(&message)?;
        Ok(Self {
            to: None,
            topics: Vec::new(),
            data: encoded,
            reference: Some(reference),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Inbound {
    pub from: PeerId,
    pub data: Vec<u8>,
    pub reference: Option<Reference>,
}

enum Command {
    Publish(Outbound),
    DialUnknown(Multiaddr),
    Listen(Multiaddr),
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: GossipsubBehaviour,
    dm: ReqRespBehaviour<DMCodec>,
    mdns: mdns::tokio::Behaviour
}

pub struct ExecutorChannel {
    channel: ResponseChannel<DMResponse>,
}

impl ExecutorChannel {
    pub fn new(channel: ResponseChannel<DMResponse>) -> Self {
        Self { channel }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Hash, Serialize, Deserialize, Copy)]
pub struct Reference {
    req_id: u64,
}

impl Default for Reference {
    fn default() -> Self {
        Self::new()
    }
}

impl Reference {
    pub fn new() -> Self {
        let rng: u64 = random();
        Self { req_id: rng }
    }
}

pub struct Networking {
    swarm: Swarm<Behaviour>,
    cmd_tx: mpsc::Sender<Command>,
    cmd_rx: mpsc::Receiver<Command>,
    inbound_tx: mpsc::Sender<Inbound>,
    broadcast_rx: broadcast::Receiver<Outbound>,
    pending_pool: HashMap<Reference, ExecutorChannel>,
}

impl Networking {
    pub async fn worker(&mut self) -> Result<()> {
        let mut bcast_rx = self.broadcast_rx.resubscribe();

        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            while let Ok(out) = bcast_rx.recv().await {
                cmd_tx.send(Command::Publish(out)).await.unwrap();
            }
        });

        loop {
            select! {
                biased;

                maybe_cmd = self.cmd_rx.recv() => {
                    if let Some(cmd) = maybe_cmd {
                        self.handle_command(cmd);
                    } else {
                        break;
                    }
                }

                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await
                }
            }
        }

        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("listen: {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("connected: {peer_id}");
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::info!("outgoing error to {:?}: {error:?}", peer_id);
            }
            SwarmEvent::IncomingConnectionError {
                send_back_addr,
                error,
                ..
            } => {
                tracing::info!("incoming error from {send_back_addr}: {error:?}");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(GossipsubEvent::Subscribed {
                peer_id,
                topic,
            })) => {
                tracing::info!("subscribed {peer_id} {topic}");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(GossipsubEvent::Message {
                propagation_source,
                message,
                ..
            })) => {
                
                self.inbound_tx
                    .send(Inbound {
                        from: propagation_source,
                        data: message.data.clone(),
                        reference: None,
                    })
                    .await
                    .unwrap();
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dm(ReqRespEvent::Message {
                peer,
                message,
                connection_id,
            })) => match message {
                ReqRespMessage::Request {
                    request: DMRequest(bytes),
                    channel,
                    ..
                } => {
                    let reference = Reference::new();
                    self.inbound_tx
                        .send(Inbound {
                            from: peer,
                            data: bytes.clone(),
                            reference: Some(reference),
                        })
                        .await
                        .unwrap();

                    self.push_to_pending(reference, ExecutorChannel::new(channel));
                }
                ReqRespMessage::Response {
                    response: DMResponse(bytes),
                    ..
                } => {
                    self.inbound_tx
                        .send(Inbound {
                            from: peer,
                            data: bytes.clone(),
                            reference: None,
                        })
                        .await
                        .unwrap();
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, _multiaddr) in list {
                    println!("mDNS discovered a new peer: {peer_id}");
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                }
            }
            _ => {}
        }
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Publish(out) => {
                tracing::info!("got publish command from application.");
                if let Some(reference) = out.reference {
                    self.respond_to_executor(reference, out.data).unwrap();
                } else if let Some(peer) = out.to {
                    let _rid = self
                        .swarm
                        .behaviour_mut()
                        .dm
                        .send_request(&peer, DMRequest(out.data.clone()));
                } else {
                    
                    for t in out.topics {
                        tracing::info!("broadcasting to overlay with topic {:?}", t);
                        let publish_result = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(gossipsub::IdentTopic::new(t.clone()), out.data.clone());
                        tracing::info!("published {:?}",publish_result);
                    }
                }
            }
            Command::DialUnknown(addr) => {
                let _ = self
                    .swarm
                    .dial(DialOpts::unknown_peer_id().address(addr).build());
            }
            Command::Listen(addr) => {
                let _ = self.swarm.listen_on(addr);
            }
        }
    }

    fn push_to_pending(&mut self, reference: Reference, connection: ExecutorChannel) {
        self.pending_pool.insert(reference, connection);
    }

    fn respond_to_executor(
        &mut self,
        reference: Reference,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let connection = self
            .pending_pool
            .remove(&reference)
            .ok_or(anyhow::anyhow!("reference doesn't exist in cache"))?;
        self.swarm
            .behaviour_mut()
            .dm
            .send_response(connection.channel, DMResponse(payload))
            .unwrap();

        Ok(())
    }

    pub async fn dial_unknown(&self, addr: Multiaddr) -> Result<()> {
        self.cmd_tx.send(Command::DialUnknown(addr)).await?;
        Ok(())
    }

    pub async fn listen(&self, addr: Multiaddr) -> Result<()> {
        self.cmd_tx.send(Command::Listen(addr)).await?;
        Ok(())
    }

    pub fn connect(&mut self, peer_addr: &Multiaddr) -> Result<ConnectionId, DialError> {
        let opt = DialOpts::from(peer_addr.clone());
        let connection_id = opt.connection_id();

        tracing::debug!("attempting to dial {peer_addr}. connection_id:{connection_id:?}");
        self.swarm.dial(opt)?;
        Ok(connection_id)
    }
}

pub fn build_overlay(
    topics: Vec<String>,
) -> Result<(
    mpsc::Receiver<Inbound>,
    broadcast::Sender<Outbound>,
    Networking,
)> {
    let mut swarm: Swarm<Behaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_dns()?
        .with_behaviour(|kp: &Keypair| {
            // gossipsub
            let cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .build()
                .unwrap();
            let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    kp.public().to_peer_id(),
                )?;
            let gossipsub =
                GossipsubBehaviour::new(MessageAuthenticity::Signed(kp.clone()), cfg).unwrap();

            let dm_cfg = ReqRespConfig::default().with_request_timeout(Duration::from_secs(20));
            let dm =
                ReqRespBehaviour::new(core::iter::once((DM_PROTO, ProtocolSupport::Full)), dm_cfg);

            Ok(Behaviour { gossipsub, dm, mdns })
        })?
        .build();

    for t in topics {
        let tp = gossipsub::IdentTopic::new(t);
        tracing::info!("subscribing to topic {:?}", tp);
        let _ = swarm.behaviour_mut().gossipsub.subscribe(&tp)?;
    }

    let _ = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?);

    let (inbound_tx, inbound_rx) = mpsc::channel::<Inbound>(1024);
    let (outbound_tx, outbound_rx) = broadcast::channel::<Outbound>(1024);
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(1024);

    let net = Networking {
        swarm,
        cmd_tx,
        cmd_rx,
        inbound_tx,
        broadcast_rx: outbound_rx,
        pending_pool: HashMap::new(),
    };

    Ok((inbound_rx, outbound_tx, net))
}
