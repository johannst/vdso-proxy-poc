use goblin::elf::{program_header::PT_LOAD, Elf};
use std::convert::TryFrom;
use vdso_proxy_poc::{Error, JmpPad, MapEntry, Mmap, VirtAddr};

#[cfg(not(target_os = "linux"))]
compile_error!("This only makes sense on Linux, as we are poking the vdso.");

struct Sym<'a>(&'a str);
struct Symver<'a>(&'a str);

/// Find the `[vdso]` entry in `/proc/self/maps`.
fn get_vdso() -> Result<MapEntry, Error> {
    for line in std::fs::read_to_string("/proc/self/maps")
        .map_err(|_| Error::FailedToReadMaps)?
        .lines()
    {
        let map = MapEntry::from_line(line)?;
        match &map.name {
            Some(n) if n == "[vdso]" => return Ok(map),
            _ => {}
        }
    }
    Err(Error::VdsoSegmentNotFound)
}

/// Create a copy of the `vdso` memory segment. Effectively allocates memory and copies the virtual
/// address range described by `vdso`.
///
/// # Safety:
/// The caller must guarantee that the `vdso` argument describes a valid virtual address range by
/// its `address` and `length` fields.
#[allow(unused_unsafe)]
unsafe fn copy_vdso(vdso: &MapEntry) -> Option<Mmap> {
    let bytes = {
        let ptr = vdso.addr as *const u8;
        let len = usize::try_from(vdso.len)
            .expect("It's required that the segment length fits into a usize!");
        // SAFETY: Validity of ptr & len must be ensured by the caller.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };

    Mmap::new_rwx_from(&bytes)
}

/// Find the `symbol_name` in the vdso described by the [`MapEntry`] memory segment.
///
/// # Safety:
/// The caller must guarantee that the `vdso` argument describes a valid virtual address range by
/// its `address` and `length` fields.
#[allow(unused_unsafe)]
unsafe fn get_vdso_sym(
    vdso: &MapEntry,
    symbol_name: Sym,
    symbol_version: Symver,
) -> Result<VirtAddr, Error> {
    // Turn `vdso` maps entry into slice of bytes.
    let bytes = {
        let ptr = vdso.addr as *const u8;
        let len = usize::try_from(vdso.len)
            .expect("It's required that the segment length fits into a usize!");
        // SAFETY: Validity of ptr & len must be ensured by the caller.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };

    // Parse vdso bytes as ELF.
    let elf = Elf::parse(bytes).map_err(|_| Error::FailedToParseAsElf)?;

    // Compute the dynamic shared object (dso) base address. Symbol offsets are relative to this
    // dso base address.
    let dso_base = {
        let phdr_load = elf
            .program_headers
            .iter()
            .find(|p| p.p_type == PT_LOAD)
            .ok_or(Error::LoadPhdrNotFound)?;
        vdso.addr - phdr_load.p_offset - phdr_load.p_vaddr
    };
    assert_ne!(dso_base, 0, "If the dso base address is 0 that means the symbols contain absolute addresses, we don't want to support that!");

    // Try to find the requested symbol.
    let (idx, sym) = elf
        .dynsyms
        .iter()
        .enumerate()
        .filter(|(_, sym)| sym.is_function())
        .find(
            |(_, sym)| matches!(elf.dynstrtab.get_at(sym.st_name), Some(sym) if sym == symbol_name.0),
        )
        .ok_or(Error::SymbolNotFound(symbol_name.0.into()))?;

    let found_symbol_version = elf
        .versym
        .ok_or(Error::SymbolVersionError(
            "Missing ELF section Versym".into(),
        ))?
        .get_at(idx)
        .ok_or(Error::SymbolVersionError(format!(
            "No Versym entry for symbol with idx {} found",
            idx
        )))?
        .find_version(elf.verdef.as_ref(), elf.verneed.as_ref(), &elf.dynstrtab)
        .ok_or(Error::SymbolVersionError(format!(
            "No symbol version string found for symbol with idx {}",
            idx
        )))?;

    if found_symbol_version != symbol_version.0 {
        return Err(Error::SymbolVersionError(format!(
            "Symbol version missmatch, want {} but found {}",
            symbol_version.0, found_symbol_version
        )));
    };

    // Compute the absolute virtual address of the requested symbol.
    Ok(VirtAddr(dso_base + sym.st_value))
}

/// Represent the `struct timeval` C structure (see `man 2 gettimeofday`).
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

fn main() -> Result<(), Error> {
    // This represents the _new_ vdso pages that the kernel mapped into the restoring process.
    let orig_vdso = get_vdso()?;

    // This represents the _old_ vdso pages that were captured in the memory dump of the process
    // checkpoint.
    //
    // SAFETY: orig_vdso describes a valid memory region as we got it from /proc/self/maps.
    let copy_vdso = unsafe { copy_vdso(&orig_vdso).expect("Copy of vdso must succeed!") };

    let (orig_sym_addr, copy_sym_addr) = unsafe {
        // SAFETY: orig_vdso describes a valid memory region as we got it from /proc/self/maps.
        let orig = get_vdso_sym(&orig_vdso, Sym("__vdso_gettimeofday"), Symver("LINUX_2.6"))?;
        // SAFETY: copy_vdso describes a valid and owned memory allocation.
        let copy = get_vdso_sym(&copy_vdso.as_ref(), Sym("__vdso_gettimeofday"), Symver("LINUX_2.6"))?;

        (orig, copy)
    };

    // As an example, install a trampoline for the `__vdso_gettimeofday` symbol. The trampoline is
    // installed in the _old_ vdso pages, where the user code from the checkpoint image binds to,
    // and forwards the calls into the _new_ vdso pages.
    let pad = JmpPad::to(orig_sym_addr);
    // SAFETY: copy_sym_addr is a valid virtual address as we got it from the symbol lookup.
    unsafe { pad.install_at(copy_sym_addr) };

    let mut tv: Timeval = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };

    unsafe {
        // Mimic a call to `__vdso_gettimeofday` from user code which binds to the _old_ vdso.

        // SAFETY: copy_sym_addr is a valid virtual address pointing to the `__vdso_gettimeofday`
        // function.
        let gettimeofday: extern "C" fn(*mut Timeval, *mut libc::c_void) -> i32 =
            std::mem::transmute(copy_sym_addr.0 as *const ());

        // Invoke the `__vdso_gettimeofday` function in the copied memory region (_old_ vdso). This
        // should forward to the function in the original memory region.
        gettimeofday(&mut tv as *mut Timeval, std::ptr::null_mut());
    }

    println!("Timeval tv_sec : {} tv_usec : {}", tv.tv_sec, tv.tv_usec);

    Ok(())
}
