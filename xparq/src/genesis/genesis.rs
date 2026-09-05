pub const BLOCKCHAIN_NAME: &str = "XPARQ";
pub const NETWORK_ID: &str = "747";
pub const NETWORK_MAGIC: [u8; 5] = *b"XPARQ";
pub const GENESIS_HEIGHT: u8 = 0;
pub const GENESIS_MESSAGE: &[u8] = b"XPARQ Genesis";

const_assert!(BLOCKCHAIN_NAME == "XPARQ");
const_assert!(NETWORK_ID == "747");
const_assert!(GENESIS_HEIGHT == 0);



#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisHeader {
    pub blockchain: &'static str,
    pub network_id: &'static str,
    pub network_magic: [u8; 5],
    pub height: u8,
}

impl GenesisHeader {
    pub const fn new() -> Self {
        Self {
            blockchain: BLOCKCHAIN_NAME,
            network_id: NETWORK_ID,
            network_magic: NETWORK_MAGIC,
            height: GENESIS_HEIGHT,
        }
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisBody {
    pub message: &'static [u8],
}

impl GenesisBody {
    pub const fn new() -> Self {
        Self {
            message: GENESIS_MESSAGE,
        }
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisBlock {
    pub header: GenesisHeader,
    pub body: GenesisBody,
}

impl GenesisBlock {
    pub const fn new() -> Self {
        Self {
            header: GenesisHeader::new(),
            body: GenesisBody::new(),
        }
    }
}