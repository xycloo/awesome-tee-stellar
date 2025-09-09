use libp2p::request_response::Codec as ReqRespCodec;

pub const DM_PROTO: &str = "/dm/1";

#[derive(Clone, Debug, Default)]
pub struct DMCodec;

#[derive(Clone, Debug)]
pub struct DMRequest(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct DMResponse(pub Vec<u8>);

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn read_u16_be<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<u16> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    Ok(u16::from_be_bytes(len_buf))
}
async fn write_u16_be<W: AsyncWrite + Unpin>(w: &mut W, n: u16) -> std::io::Result<()> {
    w.write_all(&n.to_be_bytes()).await
}

#[async_trait::async_trait]
impl ReqRespCodec for DMCodec {
    type Protocol = &'static str;
    type Request = DMRequest;
    type Response = DMResponse;

    async fn read_request<T>(
        &mut self,
        _: &&'static str,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = read_u16_be(io).await? as usize;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(DMRequest(buf))
    }

    async fn read_response<T>(
        &mut self,
        _: &&'static str,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = read_u16_be(io).await? as usize;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(DMResponse(buf))
    }

    async fn write_request<T>(
        &mut self,
        _: &&'static str,
        io: &mut T,
        DMRequest(data): DMRequest,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_u16_be(io, data.len() as u16).await?;
        io.write_all(&data).await?;
        io.flush().await
    }

    async fn write_response<T>(
        &mut self,
        _: &&'static str,
        io: &mut T,
        DMResponse(data): DMResponse,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_u16_be(io, data.len() as u16).await?;
        io.write_all(&data).await?;
        io.flush().await
    }
}
