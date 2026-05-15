//! User-defined task extended data.

use alloc::{collections::BTreeMap, vec::Vec};
use core::alloc::Layout;
use core::mem::{align_of, size_of};

use kspin::SpinNoIrq;
use lazyinit::LazyInit;

#[unsafe(no_mangle)]
#[linkage = "weak"]
static __AX_TASK_EXT_SIZE: usize = 0;

#[unsafe(no_mangle)]
#[linkage = "weak"]
static __AX_TASK_EXT_ALIGN: usize = 0;

#[unsafe(no_mangle)]
#[linkage = "weak"]
unsafe extern "C" fn __ax_task_ext_drop(_ptr: *mut u8) {}

/// A wrapper of pointer to the task extended data.
pub(crate) struct AxTaskExt {
    ptr: *mut u8,
}

fn task_ext_cache() -> &'static SpinNoIrq<BTreeMap<(usize, usize), Vec<usize>>> {
    static CACHE: LazyInit<SpinNoIrq<BTreeMap<(usize, usize), Vec<usize>>>> = LazyInit::new();
    if let Some(cache) = CACHE.get() {
        cache
    } else {
        CACHE.init_once(SpinNoIrq::new(BTreeMap::new()))
    }
}

const TASK_EXT_CACHE_LIMIT_PER_LAYOUT: usize = 256;

impl AxTaskExt {
    /// Returns the expected size of the task extended structure.
    pub fn size() -> usize {
        unsafe extern "C" {
            static __AX_TASK_EXT_SIZE: usize;
        }
        unsafe { __AX_TASK_EXT_SIZE }
    }

    /// Returns the expected alignment of the task extended structure.
    pub fn align() -> usize {
        unsafe extern "C" {
            static __AX_TASK_EXT_ALIGN: usize;
        }
        unsafe { __AX_TASK_EXT_ALIGN }
    }

    /// Construct an empty task extended structure that contains no data
    /// (zero size).
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
        }
    }

    /// Returns `true` if the task extended structure is empty.
    pub const fn is_empty(&self) -> bool {
        self.ptr.is_null()
    }

    /// Allocates the space for the task extended data, but does not
    /// initialize the data.
    pub unsafe fn uninited() -> Self {
        let size = Self::size();
        let align = Self::align();
        let ptr = if size == 0 {
            core::ptr::null_mut()
        } else {
            let cache_key = (size, align);
            if let Some(ptr) = task_ext_cache()
                .lock()
                .get_mut(&cache_key)
                .and_then(|cached| cached.pop())
            {
                ptr as *mut u8
            } else {
                let layout = Layout::from_size_align(size, align).unwrap();
                unsafe { alloc::alloc::alloc(layout) }
            }
        };
        Self { ptr }
    }

    /// Gets the raw pointer to the task extended data.
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Write the given object to the task extended data.
    ///
    /// Returns [`None`] if the data size is zero, otherwise returns a mutable
    /// reference to the content.
    ///
    /// # Panics
    ///
    /// Panics If the sizes and alignments of the two object do not match.
    pub fn write<T: Sized>(&mut self, data: T) -> Option<&mut T> {
        let data_size = size_of::<T>();
        let data_align = align_of::<T>();
        if data_size != Self::size() {
            panic!("size mismatch: {} != {}", data_size, Self::size());
        }
        if data_align != Self::align() {
            panic!("align mismatch: {} != {}", data_align, Self::align());
        }

        if self.ptr.is_null() {
            *self = unsafe { Self::uninited() };
        }
        if data_size > 0 {
            let ptr = self.ptr as *mut T;
            assert!(!ptr.is_null());
            unsafe {
                ptr.write(data);
                Some(&mut *ptr)
            }
        } else {
            None
        }
    }
}

impl Drop for AxTaskExt {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe extern "C" {
                fn __ax_task_ext_drop(ptr: *mut u8);
            }
            let layout = Layout::from_size_align(Self::size(), Self::align()).unwrap();
            unsafe {
                __ax_task_ext_drop(self.ptr);
            };
            let cache_key = (layout.size(), layout.align());
            let mut cache = task_ext_cache().lock();
            let entry = cache.entry(cache_key).or_default();
            if entry.len() < TASK_EXT_CACHE_LIMIT_PER_LAYOUT {
                entry.push(self.ptr as usize);
            } else {
                drop(cache);
                unsafe {
                    alloc::alloc::dealloc(self.ptr, layout);
                };
            };
        }
    }
}

/// A trait to convert [`TaskInner::task_ext_ptr`] to the reference of the
/// concrete type.
///
/// [`TaskInner::task_ext_ptr`]: crate::TaskInner::task_ext_ptr
pub trait TaskExtRef<T: Sized> {
    /// Get a reference to the task extended data.
    fn task_ext(&self) -> &T;
}

/// A trait to convert [`TaskInner::task_ext_ptr`] to the mutable reference of
/// the concrete type.
///
/// [`TaskInner::task_ext_ptr`]: crate::TaskInner::task_ext_ptr
pub trait TaskExtMut<T: Sized> {
    /// Get a mutable reference to the task extended data.
    fn task_ext_mut(&mut self) -> &mut T;
}

/// Define the task extended data.
///
/// It automatically implements [`TaskExtRef`] and [`TaskExtMut`] for
/// [`TaskInner`].
///
/// # Example
///
/// ```
/// # #![allow(non_local_definitions)]
/// use axtask::{def_task_ext, TaskExtRef, TaskInner};
///
/// pub struct TaskExtImpl {
///    proc_id: usize,
/// }
///
/// def_task_ext!(TaskExtImpl);
///
/// axtask::init_scheduler();
///
/// let mut inner = TaskInner::new(|| {},  "".into(), 0x1000);
/// assert!(inner.init_task_ext(TaskExtImpl { proc_id: 233 }).is_some());
/// // cannot initialize twice
/// assert!(inner.init_task_ext(TaskExtImpl { proc_id: 0xdead }).is_none());
///
/// let task = axtask::spawn_task(inner);
/// assert_eq!(task.task_ext().proc_id, 233);
/// ```
///
/// [`TaskInner`]: crate::TaskInner
#[macro_export]
macro_rules! def_task_ext {
    ($task_ext_struct:ty) => {
        #[unsafe(no_mangle)]
        static __AX_TASK_EXT_SIZE: usize = ::core::mem::size_of::<$task_ext_struct>();

        #[unsafe(no_mangle)]
        static __AX_TASK_EXT_ALIGN: usize = ::core::mem::align_of::<$task_ext_struct>();

        #[unsafe(no_mangle)]
        unsafe extern "C" fn __ax_task_ext_drop(ptr: *mut u8) {
            unsafe {
                ::core::ptr::drop_in_place(ptr as *mut $task_ext_struct);
            }
        }

        impl $crate::TaskExtRef<$task_ext_struct> for $crate::TaskInner {
            fn task_ext(&self) -> &$task_ext_struct {
                unsafe {
                    let ptr = self.task_ext_ptr() as *const $task_ext_struct;
                    assert!(!ptr.is_null());
                    &*ptr
                }
            }
        }

        impl $crate::TaskExtMut<$task_ext_struct> for $crate::TaskInner {
            fn task_ext_mut(&mut self) -> &mut $task_ext_struct {
                unsafe {
                    let ptr = self.task_ext_ptr() as *mut $task_ext_struct;
                    assert!(!ptr.is_null());
                    &mut *ptr
                }
            }
        }
    };
}
