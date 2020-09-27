#[cfg(target_os = "windows")]
pub mod win;
#[cfg(target_os = "windows")]
pub use self::win::*;

#[cfg(target_os = "linux")]
pub mod unix;
#[cfg(target_os = "linux")]
pub use self::unix::*;

#[cfg(target_os = "macos")]
pub mod unix;
#[cfg(target_os = "macos")]
pub use self::unix::*;