use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Debug, clap::Parser)]
#[command()]
pub struct Arg {
    #[command(subcommand)]
    subcommand: SubCommand,
    #[clap(short, long, env)]
    password: Option<String>,
    #[clap(
        short,
        long,
        env,
        alias = "endpoint",
        default_value = "localhost:27015"
    )]
    server: String,
}

#[derive(Debug, clap::Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum SubCommand {
    Repl,
    Exec {
        command: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let arg = Arg::parse();
    match arg.subcommand {
        SubCommand::Repl => repl(arg.server, arg.password).await,
        SubCommand::Exec { command: cmd} => command(arg.server, arg.password, cmd).await,
    }
}

async fn command(server: String, password: Option<String>, command: String) -> anyhow::Result<()> {
    let ct = CancellationToken::new();
    let quit_signal = tokio::signal::ctrl_c();

    tokio::spawn({
        let ct = ct.clone();
        async move {
            quit_signal.await.unwrap();
            ct.cancel();
        }
    });
    let stream = tokio::select! {
        _ = ct.cancelled() => {
            return Ok(());
        }
        stream = tokio::net::TcpStream::connect(server) => {
            stream
        }
    }?;
    let handle = rcon_tokio::ClientServiceHandle::initialize(
        stream,
        password.map(Into::into),
        CancellationToken::new(),
    )
    .await?;
    let client = handle.client();
    let response = client.command(command).await?;
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}

async fn repl(server: String, password: Option<String>) -> anyhow::Result<()> {
    let stream = tokio::net::TcpStream::connect(server).await?;
    let quit_signal = tokio::signal::ctrl_c();
    let ct = CancellationToken::new();
    tokio::spawn({
        let ct = ct.clone();
        async move {
            quit_signal.await.unwrap();
            ct.cancel();
        }
    });
    let handle =
        rcon_tokio::ClientServiceHandle::initialize(stream, password.map(Into::into), ct.clone())
            .await?;
    let client = handle.client();
    let std_in = tokio::io::stdin();
    let std_out = tokio::io::stdout();
    let mut reader = tokio::io::BufReader::new(std_in);
    let mut writer = tokio::io::BufWriter::new(std_out);
    let mut line = String::new();
    writer.write_all(b"command> ").await?;
    writer.flush().await?;
    loop {
        tokio::select! {
            result = reader.read_line(&mut line) => {
                result?;
                if line.is_empty() {
                    continue;
                }
                let response = client.command(line.clone()).await?;
                writer.write_all(b"response> ").await?;
                writer.write_all(&response).await?;
                writer.write_all(b"command> ").await?;
                println!();
                writer.flush().await?;
                line.clear();
            }
            _ = ct.cancelled() => {
                break;
            }
        }
    }

    Ok(())
    // Handle user input and send requests to the client
}
