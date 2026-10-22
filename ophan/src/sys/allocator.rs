use libmimalloc_sys::{mi_option_set, mi_option_t};

/// Global allocator (mimalloc) settings.
pub struct Allocator;

impl Allocator {
    /// `mi_option_arena_eager_commit` in mimalloc v3.
    const ARENA_EAGER_COMMIT: mi_option_t = 4;

    /// Commits arena memory on demand instead of upfront, which keeps the resident set
    /// close to the live heap.
    ///
    /// Runs as an ELF constructor: mimalloc creates its first arena on the first allocation,
    /// which happens before `main`.
    extern "C" fn configure() {
        // SAFETY: plain option setter with a valid option id, called before any allocation.
        unsafe {
            mi_option_set(Self::ARENA_EAGER_COMMIT, 0);
        }
    }
}

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static CONFIGURE_ALLOCATOR: extern "C" fn() = Allocator::configure;
