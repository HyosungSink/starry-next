use alloc::sync::Arc;
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsOps, VfsResult};
#[cfg(feature = "fatfs")]
use lazyinit::LazyInit;
#[cfg(feature = "lwext4_rs")]
use alloc::format;
#[cfg(feature = "lwext4_rs")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "fatfs")]
use crate::dev::{SharedRamDisk, SharedRamDiskHandle};
#[cfg(feature = "lwext4_rs")]
use crate::dev::{SharedRamDisk as Ext4SharedRamDisk, SharedRamDiskHandle as Ext4SharedRamDiskHandle};
use crate::fs;
#[cfg(feature = "lwext4_rs")]
use axdriver_block::ramdisk::RamDisk;
#[cfg(feature = "lwext4_rs")]
use axsync::Mutex;

#[cfg(feature = "fatfs")]
const BASIC_VFAT_DEV_PATH: &str = "/dev/vda2";
#[cfg(feature = "fatfs")]
const BASIC_VFAT_SIZE_BYTES: usize = 128 * 1024;

#[cfg(feature = "fatfs")]
static BASIC_VFAT_DEVICE: LazyInit<SharedRamDiskHandle> = LazyInit::new();
#[cfg(feature = "fatfs")]
static BASIC_VFAT_FS: LazyInit<Arc<fs::fatfs::FatFileSystem<SharedRamDisk>>> = LazyInit::new();
#[cfg(feature = "lwext4_rs")]
static NEXT_EXT4_MOUNT_ID: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "devfs")]
struct RandomDev;

#[cfg(feature = "devfs")]
impl VfsNodeOps for RandomDev {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new(
            VfsNodePerm::default_file(),
            VfsNodeType::CharDevice,
            0,
            0,
        ))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let mut seed = 0x6d5a_56a9_3c4f_2b17u64 ^ offset;
        for byte in buf.iter_mut() {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            *byte = seed as u8;
        }
        Ok(buf.len())
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        Ok(buf.len())
    }

    fn truncate(&self, _size: u64) -> VfsResult {
        Ok(())
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}

#[cfg(all(feature = "devfs", feature = "fatfs"))]
struct BasicFatBlockDev(SharedRamDiskHandle);

#[cfg(all(feature = "devfs", feature = "fatfs"))]
impl VfsNodeOps for BasicFatBlockDev {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let size = self.0.lock().size() as u64;
        Ok(VfsNodeAttr::new(
            VfsNodePerm::from_bits_truncate(0o660),
            VfsNodeType::BlockDevice,
            size,
            size.div_ceil(512),
        ))
    }

    fn read_at(&self, offset: u64, mut buf: &mut [u8]) -> VfsResult<usize> {
        let mut disk = SharedRamDisk::from_handle(self.0.clone());
        disk.set_position(offset);
        let mut read_len = 0;
        while !buf.is_empty() {
            match disk.read_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_len += n;
                }
                Err(_) => return Err(axfs_vfs::VfsError::Io),
            }
        }
        Ok(read_len)
    }

    fn write_at(&self, offset: u64, mut buf: &[u8]) -> VfsResult<usize> {
        let mut disk = SharedRamDisk::from_handle(self.0.clone());
        disk.set_position(offset);
        let mut write_len = 0;
        while !buf.is_empty() {
            match disk.write_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &buf[n..];
                    write_len += n;
                }
                Err(_) => return Err(axfs_vfs::VfsError::Io),
            }
        }
        Ok(write_len)
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}

#[cfg(feature = "fatfs")]
fn ensure_basic_vfat_device() -> &'static SharedRamDiskHandle {
    if !BASIC_VFAT_DEVICE.is_inited() {
        let handle = Arc::new(axsync::Mutex::new(axdriver_block::ramdisk::RamDisk::new(
            BASIC_VFAT_SIZE_BYTES,
        )));
        let mut disk = SharedRamDisk::from_handle(handle.clone());
        fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new())
            .expect("failed to format basic FAT test device");
        BASIC_VFAT_DEVICE.init_once(handle);
    }
    &BASIC_VFAT_DEVICE
}

#[cfg(feature = "fatfs")]
fn ensure_basic_vfat_fs() -> &'static Arc<fs::fatfs::FatFileSystem<SharedRamDisk>> {
    let device = ensure_basic_vfat_device().clone();
    if !BASIC_VFAT_FS.is_inited() {
        BASIC_VFAT_FS.init_once(Arc::new(fs::fatfs::FatFileSystem::new(
            SharedRamDisk::from_handle(device),
        )));
        BASIC_VFAT_FS.init();
    }
    &BASIC_VFAT_FS
}

#[cfg(feature = "fatfs")]
pub(crate) fn mountable_fat_fs(
    source: &str,
) -> Option<Arc<fs::fatfs::FatFileSystem<SharedRamDisk>>> {
    (source == BASIC_VFAT_DEV_PATH).then(|| ensure_basic_vfat_fs().clone())
}

#[cfg(feature = "lwext4_rs")]
fn ext4_ramdisk_from_bytes(image: &[u8]) -> VfsResult<Ext4SharedRamDiskHandle> {
    let size = image.len().max(512).div_ceil(512) * 512;
    let handle = Arc::new(Mutex::new(RamDisk::new(size)));
    let mut disk = Ext4SharedRamDisk::from_handle(handle.clone());
    let mut remaining = image;
    while !remaining.is_empty() {
        let written = disk.write_one(remaining).map_err(|_| axfs_vfs::VfsError::Io)?;
        if written == 0 {
            return Err(axfs_vfs::VfsError::Io);
        }
        remaining = &remaining[written..];
    }
    Ok(handle)
}

#[cfg(feature = "lwext4_rs")]
pub(crate) fn mountable_ext4_fs(
    mount_path: &str,
    image: &[u8],
) -> VfsResult<Arc<fs::lwext4_rust::RamExt4FileSystem>> {
    let disk = ext4_ramdisk_from_bytes(image)?;
    let mount_id = NEXT_EXT4_MOUNT_ID.fetch_add(1, Ordering::Relaxed);
    let device_name = format!("ext4fs{mount_id}");
    fs::lwext4_rust::RamExt4FileSystem::new(
        Ext4SharedRamDisk::from_handle(disk),
        mount_path,
        device_name.as_str(),
    )
    .map(Arc::new)
    .map_err(fs::lwext4_rust::ext4_err_to_vfs)
}

#[cfg(feature = "devfs")]
pub(crate) fn devfs() -> Arc<fs::devfs::DeviceFileSystem> {
    let null = fs::devfs::NullDev;
    let zero = fs::devfs::ZeroDev;
    let bar = fs::devfs::ZeroDev;
    let devfs = fs::devfs::DeviceFileSystem::new();
    let foo_dir = devfs.mkdir("foo");
    devfs.add("null", Arc::new(null));
    devfs.add("zero", Arc::new(zero));
    devfs.add("random", Arc::new(RandomDev));
    devfs.add("urandom", Arc::new(RandomDev));
    #[cfg(feature = "fatfs")]
    devfs.add(
        "vda2",
        Arc::new(BasicFatBlockDev(ensure_basic_vfat_device().clone())),
    );
    foo_dir.add("bar", Arc::new(bar));
    Arc::new(devfs)
}

#[cfg(feature = "ramfs")]
pub(crate) fn ramfs() -> Arc<fs::ramfs::RamFileSystem> {
    Arc::new(fs::ramfs::RamFileSystem::new())
}

#[cfg(feature = "ramfs")]
pub(crate) fn ramfs_with_max_bytes(max_bytes: Option<usize>) -> Arc<fs::ramfs::RamFileSystem> {
    Arc::new(fs::ramfs::RamFileSystem::new_with_max_bytes(max_bytes))
}

#[cfg(feature = "lwext4_rs")]
pub(crate) fn reclaim_mount_caches() -> usize {
    let (reclaimed_dir_entries, reclaimed_nodes) = fs::lwext4_rust::reclaim_shared_caches();
    reclaimed_dir_entries + reclaimed_nodes
}

#[cfg(not(feature = "lwext4_rs"))]
pub(crate) fn reclaim_mount_caches() -> usize {
    0
}

#[cfg(feature = "procfs")]
pub(crate) fn procfs() -> VfsResult<Arc<fs::ramfs::RamFileSystem>> {
    let procfs = fs::ramfs::RamFileSystem::new();
    let proc_root = procfs.root_dir();

    // Create /proc/sys/net/core/somaxconn
    proc_root.create("sys", VfsNodeType::Dir)?;
    proc_root.create("sys/net", VfsNodeType::Dir)?;
    proc_root.create("sys/net/core", VfsNodeType::Dir)?;
    proc_root.create("sys/net/core/somaxconn", VfsNodeType::File)?;
    let file_somaxconn = proc_root.clone().lookup("./sys/net/core/somaxconn")?;
    file_somaxconn.write_at(0, b"4096\n")?;

    // Create /proc/sys/vm/overcommit_memory
    proc_root.create("sys/vm", VfsNodeType::Dir)?;
    proc_root.create("sys/vm/overcommit_memory", VfsNodeType::File)?;
    let file_over = proc_root.clone().lookup("./sys/vm/overcommit_memory")?;
    file_over.write_at(0, b"0\n")?;

    // Create /proc/sys/kernel/*
    proc_root.create("sys/kernel", VfsNodeType::Dir)?;
    proc_root.create("sys/kernel/pid_max", VfsNodeType::File)?;
    proc_root.create("sys/kernel/tainted", VfsNodeType::File)?;
    proc_root.create("sys/kernel/keys", VfsNodeType::Dir)?;
    proc_root.create("sys/kernel/keys/root_maxkeys", VfsNodeType::File)?;
    proc_root.create("sys/kernel/keys/root_maxbytes", VfsNodeType::File)?;
    proc_root.create("sys/kernel/keys/maxkeys", VfsNodeType::File)?;
    proc_root.create("sys/kernel/keys/maxbytes", VfsNodeType::File)?;
    proc_root.create("sys/kernel/keys/gc_delay", VfsNodeType::File)?;
    proc_root
        .clone()
        .lookup("./sys/kernel/pid_max")?
        .write_at(0, b"32768\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/tainted")?
        .write_at(0, b"0\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/keys/root_maxkeys")?
        .write_at(0, b"1000\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/keys/root_maxbytes")?
        .write_at(0, b"25000000\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/keys/maxkeys")?
        .write_at(0, b"1000\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/keys/maxbytes")?
        .write_at(0, b"25000000\n")?;
    proc_root
        .clone()
        .lookup("./sys/kernel/keys/gc_delay")?
        .write_at(0, b"5\n")?;

    // Create /proc/self/stat
    proc_root.create("self", VfsNodeType::Dir)?;
    proc_root.create("self/stat", VfsNodeType::File)?;

    Ok(Arc::new(procfs))
}

#[cfg(feature = "sysfs")]
pub(crate) fn sysfs() -> VfsResult<Arc<fs::ramfs::RamFileSystem>> {
    let sysfs = fs::ramfs::RamFileSystem::new();
    let sys_root = sysfs.root_dir();

    // Create /sys/kernel/mm/transparent_hugepage/enabled
    sys_root.create("kernel", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm/transparent_hugepage", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm/transparent_hugepage/enabled", VfsNodeType::File)?;
    let file_hp = sys_root
        .clone()
        .lookup("./kernel/mm/transparent_hugepage/enabled")?;
    file_hp.write_at(0, b"always [madvise] never\n")?;

    // Create /sys/devices/system/clocksource/clocksource0/current_clocksource
    sys_root.create("devices", VfsNodeType::Dir)?;
    sys_root.create("devices/system", VfsNodeType::Dir)?;
    sys_root.create("devices/system/clocksource", VfsNodeType::Dir)?;
    sys_root.create("devices/system/clocksource/clocksource0", VfsNodeType::Dir)?;
    sys_root.create(
        "devices/system/clocksource/clocksource0/current_clocksource",
        VfsNodeType::File,
    )?;
    let file_cc = sys_root
        .clone()
        .lookup("devices/system/clocksource/clocksource0/current_clocksource")?;
    file_cc.write_at(0, b"tsc\n")?;

    sys_root.create("block", VfsNodeType::Dir)?;
    sys_root.create("block/loop0", VfsNodeType::Dir)?;
    sys_root.create("block/loop0/queue", VfsNodeType::Dir)?;
    sys_root.create("block/loop0/queue/logical_block_size", VfsNodeType::File)?;
    let logical = sys_root
        .clone()
        .lookup("block/loop0/queue/logical_block_size")?;
    logical.write_at(0, b"512\n")?;
    sys_root.create("block/loop0/queue/dma_alignment", VfsNodeType::File)?;
    let dma = sys_root
        .clone()
        .lookup("block/loop0/queue/dma_alignment")?;
    dma.write_at(0, b"511\n")?;

    Ok(Arc::new(sysfs))
}
