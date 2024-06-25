fn main() {}

mod tests {
    use ethers::middleware::{Middleware, SignerMiddleware};
    use ethers::providers::{Provider, Ws};
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::{BlockId, BlockNumber, Filter, Transaction, TransactionRequest, U256, U64};
    use ethers::utils;
    use std::io::{self, Read};
    use tracing::{info, Level};
    use tracing_subscriber::FmtSubscriber;

    fn init_tracing() {
        // a builder for `FmtSubscriber`.
        let subscriber = FmtSubscriber::builder()
            // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
            // will be written to stdout.
            .with_max_level(Level::INFO)
            // completes the builder.
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }

    #[tokio::test]
    async fn get_chain_info() {
        // Initialize logging for tracing the execution
        init_tracing();

        // WebSocket URL for connecting to the blockchain network
        const WS_URL: &str = "wss://rpc.shibuya.astar.network";

        // Private key of the sender's wallet (for demonstration purposes, this should be kept secret in a real application)
        const PRIVATE_KEY: &str =
            "0x28d9e44e255579afe7a0388cf74af1834eab8b2d14957de9ca0b40f1e2a6b2a5";

        // Destination address to which the transaction will be sent
        const DEST_ADDRESS: &str = "0x26419F973ca19429c400a6e84d59Ed5e71570b83";

        info!("Here is URL: {:?}", WS_URL);

        // Connect to the WebSocket provider
        let ws_provider = Ws::connect(WS_URL).await.unwrap();
        let provider = Provider::new(ws_provider);

        // Retrieve and log the latest block number
        let latest_block_number = provider.get_block_number().await.unwrap();
        info!("latest Block Number {:?}", latest_block_number);

        // Get the block details by the latest block number
        let block_by_number = provider.get_block(latest_block_number).await.unwrap();
        info!("get block by number {:?}", block_by_number);

        // Extract the block hash from the block details
        let block_hash = block_by_number.unwrap().hash;

        // Get the block details by the block hash
        let block_by_hash = provider.get_block(block_hash.unwrap()).await.unwrap();
        info!("get block by hash {:?}", block_by_hash);

        // Create a filter to fetch logs from the latest block number
        let filter = Filter::new().from_block(BlockNumber::Number(latest_block_number.into()));
        info!("Logs by block Number");

        // Retrieve and log the logs using the filter
        let logs = provider.get_logs(&filter).await.unwrap();
        for log in logs {
            info!("{:?}", log);
        }

        // Create a filter to fetch logs using the block hash
        let filter = Filter::new().at_block_hash(block_by_hash.unwrap().hash.unwrap());
        info!("Logs by block Hash");

        // Retrieve and log the logs using the filter
        let logs = provider.get_logs(&filter).await.unwrap();
        for log in logs {
            info!("{:?}", log);
        }

        // Log the finalized block number
        info!(
            "Finalized block {:?}",
            provider
                .get_block(BlockId::Number(BlockNumber::Finalized))
                .await
                .unwrap()
                .unwrap()
                .number
        );

        // Log account information
        info!("account info {:?}", provider.get_accounts().await);

        // Retrieve and log the chain ID
        let chain_id = provider.get_chainid().await.unwrap();

        // Parse the private key to create a local wallet
        let wallet = PRIVATE_KEY
            .parse::<LocalWallet>()
            .unwrap()
            .with_chain_id(chain_id.as_u64());

        // connect the wallet to the provider
        let client = SignerMiddleware::new(provider.clone(), wallet);

        // Create a transaction request
        let tx = TransactionRequest::new()
            .to(DEST_ADDRESS)
            .value(U256::from(utils::parse_ether(0.0001).unwrap()));

        let pending_tx = client.send_transaction(tx, None).await.unwrap();

        // Retrieve the transaction receipt and log it
        let receipt = pending_tx
            .await
            .unwrap()
            .ok_or_else(|| "tx dropped from mempool")
            .unwrap();

        // Get the transaction details using the transaction hash from the receipt
        let tx = client
            .get_transaction(receipt.transaction_hash)
            .await
            .unwrap();

        // Serialize the transaction to JSON format and log it
        let tx_json = serde_json::to_string(&tx).unwrap();
        info!("Send tx {:?}", tx_json.clone());
        info!("Tx recipt {:?}", serde_json::to_string(&receipt).unwrap());
    }
}
