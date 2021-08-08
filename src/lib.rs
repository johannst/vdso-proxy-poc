//! Collection of some abstractions and the error definition used by this PoC.

/// Errors that can occur in this PoC.
#[derive(Debug)]
pub enum Error {
    /// Failed to open and read the `/proc/self/maps` file.
    FailedToReadMaps,
    /// Failed to a parse line from the `/proc/self/maps` file.
    /// Captures line that failed to parse.
    ParseMapEntryError(String),
    /// No `[vdso]` segment found in `/proc/self/maps`.
    VdsoSegmentNotFound,
    /// Failed to parse bytes as ELF file.
    FailedToParseAsElf,
    /// No `PT_LOAD` program header found in the ELF file.
    LoadPhdrNotFound,
    /// Requested symbol not found in the ELF file.
    /// Captures the name of the requested symbol.
    SymbolNotFound(String),
}

/// Representation of an 64-bit virtual address.
#[derive(Debug, Copy, Clone)]
pub struct VirtAddr(pub u64);

/// Represents an entry from the `/proc/self/maps` file with the information needed by this PoC.
/// ```text
/// man 5 proc
///   address           perms offset  dev   inode       pathname
///   00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
/// ```
#[derive(Debug)]
pub struct MapEntry {
    /// Start address of the memory segment.
    pub addr: u64,
    /// Length of the memory segment.
    pub len: u64,
    /// Optional name of the memory segment.
    pub name: Option<String>,
}

impl MapEntry {
    /// Try to parse a [`MapEntry`] from the `line` passed as argument.
    pub fn from_line<'a>(line: &'a str) -> Result<MapEntry, Error> {
        let expect = |tok: Option<&'a str>| tok.ok_or(Error::ParseMapEntryError(line.into()));

        // Tokenize the line.
        let mut toks = line.split_whitespace();
        let addr = expect(toks.next())?;
        let _perms = expect(toks.next())?;
        let _offset = expect(toks.next())?;
        let _dev = expect(toks.next())?;
        let _inode = expect(toks.next())?;
        let name = toks.next().map(|name| String::from(name));

        // Parse the address token.
        let (addr, len) = {
            let tou64 = |s: &'a str| {
                u64::from_str_radix(s, 16)
                    .map_err(|e| Error::ParseMapEntryError(format!("{}\n{}", line, e)))
            };

            let mut toks = addr.split('-');
            let start = tou64(expect(toks.next())?)?;
            let end = tou64(expect(toks.next())?)?;

            (start, end - start)
        };

        Ok(MapEntry { addr, len, name })
    }
}

/// Owned [`libc::mmap`] allocation.
pub struct Mmap {
    ptr: *mut libc::c_void,
    len: usize,
    map: MapEntry,
}

impl Mmap {
    /// Create a new allocation with `read | write | execute` permissions big enough to hold a copy
    /// of `bytes` and initialize it with the `bytes` passed as argument.
    pub fn new_rwx_from(bytes: &[u8]) -> Option<Mmap> {
        use libc::{
            memcpy, mmap, sysconf, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ,
            PROT_WRITE, _SC_PAGESIZE,
        };

        // Get the page size.
        let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

        // Compute required size for the new allocation by rounding up to the next page size.
        let len = ((bytes.len() + page_size - 1) / page_size) * page_size;

        // Allocate new `rwx` memory segment.
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, /* fd */
                0,  /* offset */
            )
        };

        if ptr == MAP_FAILED {
            return None;
        }

        unsafe {
            // Initialize new allocation with `bytes` passed as argument.
            memcpy(ptr, bytes.as_ptr().cast(), bytes.len());
        }

        Some(Mmap {
            ptr,
            len,
            map: MapEntry {
                addr: ptr as u64,
                len: len as u64,
                name: Some("mmap_rwx".into()),
            },
        })
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

impl AsRef<MapEntry> for Mmap {
    fn as_ref(&self) -> &'_ MapEntry {
        &self.map
    }
}

impl AsMut<[u8]> for Mmap {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) }
    }
}

/// An `x86_64` jump pad (trampoline) that that can be installed at a [`VirtAddr`].
///
/// The jump pad is implemented as:
/// ```asm
/// mov rax, imm64  ; target
/// jmp rax
/// ```
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
#[repr(packed)]
pub struct JmpPad {
    movabs: u16,
    target: u64,
    jmp_rax: u16,
}

#[cfg(target_arch = "x86_64")]
impl JmpPad {
    /// Initialize a new jump pad to the destination virtual address `target`.
    /// This does not install the jump pad.
    pub fn to(target: VirtAddr) -> JmpPad {
        JmpPad {
            movabs: 0xb848, // REX.W + mov rax, imm64
            target: target.0,
            jmp_rax: 0xe0ff, // jmp rax
        }
    }

    /// Install the jump pad at the virtual address `addr`.
    ///
    /// # Safety
    /// The caller must guarantee the following constraints:
    /// - `addr` must be a valid virtual address referring to writeable memory.
    /// - There must be enough space to store [`size_of::<JmpPad>()`](core::mem::size_of) bytes.
    pub unsafe fn install_at(self, addr: VirtAddr) {
        std::ptr::write(addr.0 as *mut JmpPad, self);
    }
}
