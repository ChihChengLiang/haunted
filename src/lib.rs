mod client;
mod server;
mod types;
mod phantom;

pub use client::Wallet;
pub use server::rocket;

#[cfg(test)]
mod tests;
