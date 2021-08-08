# `vdso` proxy proof-of-concept

## Background
Simply spoken, the `vdso` is an ELF file provided by the Linux Kernel and
mapped into a process to provide the implementation of certain `syscalls` in
userspace. Userspace can call those `virtual` syscalls without invoking a
_real_ syscall (eg on x86-64 `syscall` instruction).

The location where the Kernel mapped the `vdso` can be found in the `maps`
(procfs) labeled with the `[vdso]` tag.
```bash
> cat /proc/self/maps | grep vdso
7ffeae5fb000-7ffeae5fd000 r-xp 00000000 00:00 0     [vdso]
```

More details about the `vdso` can be found here:
- https://man7.org/linux/man-pages/man7/vdso.7.html
- https://www.kernel.org/doc/Documentation/ABI/stable/vdso

## Why do this?
This is some toying around and proof-of-concept for `process-checkpoint`
scenarios with `migration` in mind.
Typically a process checkpoint contains a dump of the virtual memory regions of
a process which are then re-mapped when restoring the process at a later point
in time. The vdso in this case needs some special treatment as the user code in
the checkpoint image might have some references into the vdso segment (usually
this is done behind the scenes by the `libc`) where it was when taking the
checkpoint .
When restoring a checkpoint, the Kernel will map the `vdso` to a random virtual
address in the restoring process, therfore there are two cases to distinguish:
1. Restoring the checkpoint with the same Kernel.
1. Restoring the checkpoint with a different Kernel (`migration`).

For case `(1)` the `vdso` can be [`mremap(2)`][man-mremap]-ed to the virtual
address where the vdso resided when creating the checkpoint. This is fine
because the _new_ and the _old_ `vdso` are compatible.

For case `(2)` however it is possible that the binary layout of the _new_
`vdso` has changed (eg different offsets for a given symbol) and is therefore
incompatible with the _old_ `vdso`. In that case a simple
[`mremap(2)`][man-mremap] won't do the trick.
This case is explored in this repository with a `proxy` mechanism which is
described by the figure below.

```text
# Before checkpoint create.

          VMA
          +---------------------+
          | libc:               |
          | gettimeofday(...)   |
          |   ..                |
          |   call              | --+
          |   ..                |   | User code binds to symbols in the vdso.
eg    +-- +---------------------+   |
+0x10 |   | vdso:               |   |
      +-> | __vdso_gettimeofday | <-+
          |   ..                |
          +---------------------+


# After checkpoint restore.

          VMA
          +---------------------+
          | libc:               |
          | gettimeofday(...)   |
          |   ..                |
          |   call              | --+
          |   ..                |   | After restoring the memory of the process checkpoint,
eg    +-- +---------------------+   | user code still binds to symbols in the _old_ vdso region.
+0x10 |   | [old] vdso:         |   |
      +-> | __vdso_gettimeofday | <-+
          |   jmp               | --+
          |   ..                |   | After restore, the functions in the _old_ vdso region
eg    +-- +---------------------+   | are patched with a trampoline forwarding to the
+0x40 |   | [new] vdso:         |   | corresponding function in the _new_ vdso region.
      +-> | __vdso_gettimeofday | <-+
          |   ..                |
          +---------------------+
```

This approach introduces the need for a higher-level synchronization as it must
be ensured that no thread is in the middle of executing a `vdso` function when
creating the process checkpoint. This PoC doesn't take this into account as it
merely focuses on the mechanics described above.

## License
This project is licensed under the [MIT](LICENSE) license.

[man-mremap]: https://man7.org/linux/man-pages/man2/mremap.2.html
