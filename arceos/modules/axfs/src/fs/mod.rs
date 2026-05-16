#[cfg(feature = "myfs")]
pub mod myfs;

#[cfg(feature = "lwext4_rs")]
pub mod lwext4_rust;

#[cfg(feature = "fatfs")]
pub mod fatfs;

#[cfg(feature = "devfs")]
pub use axfs_devfs as devfs;

#[cfg(feature = "ramfs")]
pub use axfs_ramfs as ramfs;
