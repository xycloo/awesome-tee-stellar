//! Common crate for the stellar node implementation.
//!
//! If you want to write the clients for other chains you should fork this crate to work off those chain types.
//! Common could potentially be implemented so that it's chain agnostic but it's out of the scope right now.
//!

pub mod crypto;
pub mod message;
pub mod networking;
