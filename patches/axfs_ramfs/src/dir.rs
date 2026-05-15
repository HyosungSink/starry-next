use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::{string::String, vec::Vec};

use axfs_vfs::{VfsDirEntry, VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeRef, VfsNodeType};
use axfs_vfs::{VfsError, VfsResult};
use spin::RwLock;

use crate::FsQuota;
use crate::file::FileNode;

/// The directory node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct DirNode {
    this: Weak<DirNode>,
    parent: RwLock<Weak<dyn VfsNodeOps>>,
    children: RwLock<BTreeMap<String, VfsNodeRef>>,
    perm: RwLock<VfsNodePerm>,
    quota: Arc<FsQuota>,
}

impl DirNode {
    pub(super) fn new(parent: Option<Weak<dyn VfsNodeOps>>, quota: Arc<FsQuota>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            parent: RwLock::new(parent.unwrap_or_else(|| Weak::<Self>::new())),
            children: RwLock::new(BTreeMap::new()),
            perm: RwLock::new(VfsNodePerm::default_dir()),
            quota,
        })
    }

    pub(super) fn set_parent(&self, parent: Option<&VfsNodeRef>) {
        *self.parent.write() = parent.map_or(Weak::<Self>::new() as _, Arc::downgrade);
    }

    pub fn set_perm(&self, perm: VfsNodePerm) {
        *self.perm.write() = perm;
    }

    /// Returns a string list of all entries in this directory.
    pub fn get_entries(&self) -> Vec<String> {
        self.children.read().keys().cloned().collect()
    }

    /// Checks whether a node with the given name exists in this directory.
    pub fn exist(&self, name: &str) -> bool {
        self.children.read().contains_key(name)
    }

    /// Creates a new node with the given name and type in this directory.
    pub fn create_node(&self, name: &str, ty: VfsNodeType) -> VfsResult {
        if self.exist(name) {
            log::error!("AlreadyExists {}", name);
            return Err(VfsError::AlreadyExists);
        }
        let node: VfsNodeRef = match ty {
            VfsNodeType::File => Arc::new(FileNode::new(self.quota.clone())),
            VfsNodeType::Fifo => Arc::new(FileNode::new_fifo(self.quota.clone())),
            VfsNodeType::Socket => Arc::new(FileNode::new_socket(self.quota.clone())),
            VfsNodeType::Dir => Self::new(Some(self.this.clone()), self.quota.clone()),
            _ => return Err(VfsError::Unsupported),
        };
        self.children.write().insert(name.into(), node);
        Ok(())
    }

    /// Removes a node by the given name in this directory.
    pub fn remove_node(&self, name: &str) -> VfsResult {
        let mut children = self.children.write();
        let node = children.get(name).ok_or(VfsError::NotFound)?;
        if let Some(dir) = node.as_any().downcast_ref::<DirNode>() {
            if !dir.children.read().is_empty() {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }
        children.remove(name);
        Ok(())
    }

    fn current_dir_arc(&self) -> VfsResult<Arc<DirNode>> {
        self.this.upgrade().ok_or(VfsError::NotFound)
    }

    fn resolve_dir_path(&self, path: &str) -> VfsResult<Arc<DirNode>> {
        let path = path.trim_matches('/');
        if path.is_empty() || path == "." {
            return self.current_dir_arc();
        }
        let node = self.current_dir_arc()?.lookup(path)?;
        node.as_any()
            .downcast_ref::<DirNode>()
            .and_then(|dir| dir.this.upgrade())
            .ok_or(VfsError::NotADirectory)
    }

    fn is_descendant_dir(ancestor: &Arc<DirNode>, mut node: Arc<DirNode>) -> bool {
        loop {
            if Arc::ptr_eq(ancestor, &node) {
                return true;
            }
            let Some(parent) = node.parent() else {
                return false;
            };
            let Some(parent_dir) = parent.as_any().downcast_ref::<DirNode>() else {
                return false;
            };
            let Some(parent_dir) = parent_dir.this.upgrade() else {
                return false;
            };
            node = parent_dir;
        }
    }
}

impl VfsNodeOps for DirNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new(*self.perm.read(), VfsNodeType::Dir, 4096, 0))
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        self.parent.read().upgrade()
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        let (name, rest) = split_path(path);
        let node = match name {
            "" | "." => Ok(self.clone() as VfsNodeRef),
            ".." => self.parent().ok_or(VfsError::NotFound),
            _ => self
                .children
                .read()
                .get(name)
                .cloned()
                .ok_or(VfsError::NotFound),
        }?;

        if let Some(rest) = rest {
            node.lookup(rest)
        } else {
            Ok(node)
        }
    }

    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        let children = self.children.read();
        let mut children = children.iter().skip(start_idx.max(2) - 2);
        for (i, ent) in dirents.iter_mut().enumerate() {
            match i + start_idx {
                0 => *ent = VfsDirEntry::new(".", VfsNodeType::Dir),
                1 => *ent = VfsDirEntry::new("..", VfsNodeType::Dir),
                _ => {
                    if let Some((name, node)) = children.next() {
                        *ent = VfsDirEntry::new(name, node.get_attr().unwrap().file_type());
                    } else {
                        return Ok(i);
                    }
                }
            }
        }
        Ok(dirents.len())
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        log::debug!("create {:?} at ramfs: {}", ty, path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.create(rest, ty),
                ".." => self.parent().ok_or(VfsError::NotFound)?.create(rest, ty),
                _ => {
                    let subdir = self
                        .children
                        .read()
                        .get(name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    subdir.create(rest, ty)
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Ok(()) // already exists
        } else {
            self.create_node(name, ty)
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        log::debug!("remove at ramfs: {}", path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.remove(rest),
                ".." => self.parent().ok_or(VfsError::NotFound)?.remove(rest),
                _ => {
                    let subdir = self
                        .children
                        .read()
                        .get(name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    subdir.remove(rest)
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Err(VfsError::InvalidInput) // remove '.' or '..
        } else {
            self.remove_node(name)
        }
    }

    fn rename(&self, src_path: &str, dst_path: &str) -> VfsResult {
        fn split_parent_and_name(path: &str) -> (&str, &str) {
            let trimmed = path.trim_matches('/');
            trimmed
                .rsplit_once('/')
                .map_or(("", trimmed), |(parent, name)| (parent, name))
        }

        let (src_parent_path, src_name) = split_parent_and_name(src_path);
        let (dst_parent_path, dst_name) = split_parent_and_name(dst_path);
        if src_name.is_empty()
            || dst_name.is_empty()
            || matches!(src_name, "." | "..")
            || matches!(dst_name, "." | "..")
        {
            return Err(VfsError::InvalidInput);
        }

        let src_parent = self.resolve_dir_path(src_parent_path)?;
        let dst_parent = self.resolve_dir_path(dst_parent_path)?;
        if Arc::ptr_eq(&src_parent, &dst_parent) && src_name == dst_name {
            return Ok(());
        }

        let src_node = {
            let children = src_parent.children.read();
            children.get(src_name).cloned().ok_or(VfsError::NotFound)?
        };

        if let Some(src_dir) = src_node
            .as_any()
            .downcast_ref::<DirNode>()
            .and_then(|dir| dir.this.upgrade())
        {
            if Self::is_descendant_dir(&src_dir, dst_parent.clone()) {
                return Err(VfsError::InvalidInput);
            }
        }

        {
            let children = dst_parent.children.read();
            if let Some(existing) = children.get(dst_name) {
                if let Some(dir) = existing.as_any().downcast_ref::<DirNode>() {
                    if !dir.children.read().is_empty() {
                        return Err(VfsError::DirectoryNotEmpty);
                    }
                }
            }
        }

        if let Some(dir) = src_node.as_any().downcast_ref::<DirNode>() {
            let dst_parent_node: VfsNodeRef = dst_parent.clone();
            dir.set_parent(Some(&dst_parent_node));
        }

        let removed = {
            let mut children = src_parent.children.write();
            children.remove(src_name).ok_or(VfsError::NotFound)?
        };

        let old = {
            let mut children = dst_parent.children.write();
            children.insert(dst_name.into(), removed)
        };

        if let Some(old) = old {
            drop(old);
        }
        Ok(())
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

fn split_path(path: &str) -> (&str, Option<&str>) {
    let trimmed_path = path.trim_start_matches('/');
    trimmed_path.find('/').map_or((trimmed_path, None), |n| {
        (&trimmed_path[..n], Some(&trimmed_path[n + 1..]))
    })
}
