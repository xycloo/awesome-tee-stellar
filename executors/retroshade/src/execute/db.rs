use postgres::NoTls;
use tokio::task::JoinHandle;
use tokio_postgres::Client;

use crate::execute::ConstructedZephyrBinary;

pub struct PgConnection {
    pub client: Client,
    // We keep the JoinHandle alive so the connection future isn't dropped.
    _connection_task: JoinHandle<()>,
}

impl PgConnection {
    pub async fn new(conn: &str) -> Result<Self, tokio_postgres::Error> {
        let (client, connection) = tokio_postgres::connect(conn, NoTls).await?;

        let connection_task = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::info!("Postgres connection error: {}", e);
            }
        });

        Ok(Self {
            client,
            _connection_task: connection_task,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

pub async fn read_binaries(client: &Client) -> anyhow::Result<Vec<ConstructedZephyrBinary>> {
    let code = client
        .prepare_typed(
            "select code, is_retroshade, contracts from public.zephyr_programs",
            &[],
        )
        .await?;

    let rows = client.query(&code, &[]).await?;
    let mut binaries = Vec::new();

    for row in rows {
        let code: Vec<u8> = row.get(0);
        let is_retroshade: bool = row.try_get(1).unwrap_or(false);

        let contracts = if is_retroshade {
            Some(row.try_get(2).unwrap_or(vec![]))
        } else {
            None
        };

        binaries.push(ConstructedZephyrBinary {
            user_id: 0,
            code,
            running: true,
            is_retroshade,
            contracts,
        })
    }

    Ok(binaries)
}
