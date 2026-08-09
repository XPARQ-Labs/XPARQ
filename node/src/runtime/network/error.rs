use crate::runtime::node::NodeError;
use borsh::io;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum NetworkError {
    MessageTooLarge,
    Node(NodeError),
    Io(io::Error),
    Serialization(io::Error),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::MessageTooLarge => f.write_str("network message exceeds maximum size"),
            NetworkError::Node(error) => write!(f, "network node handler error: {error}"),
            NetworkError::Io(error) => write!(f, "network I/O error: {error}"),
            NetworkError::Serialization(error) => {
                write!(f, "network message serialization error: {error}")
            }
        }
    }
}

impl Error for NetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NetworkError::MessageTooLarge => None,
            NetworkError::Node(error) => Some(error),
            NetworkError::Io(error) => Some(error),
            NetworkError::Serialization(error) => Some(error),
        }
    }
}

impl From<io::Error> for NetworkError {
    fn from(error: io::Error) -> Self {
        NetworkError::Serialization(error)
    }
}

impl From<NodeError> for NetworkError {
    fn from(error: NodeError) -> Self {
        NetworkError::Node(error)
    }
}
