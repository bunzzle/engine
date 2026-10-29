use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::buf::Buf;
use crate::epoll::EventFd;

const OP_FSYNC: u8 = 3;
const OP_READ: u8 = 22;
const OP_WRITE: u8 = 23;
const FSYNC_DATASYNC: u32 = 1;
const FEAT_SINGLE_MMAP: u32 = 1;
const FEAT_NODROP: u32 = 1 << 1;
const ENTER_GETEVENTS: u32 = 1;
const REGISTER_EVENTFD: u32 = 4;
const REGISTER_PROBE: u32 = 8;
const PROBE_OPS: usize = 256;
const OP_SUPPORTED: u16 = 1;
const OFF_SQ_RING: libc::off_t = 0;
const OFF_SQES: libc::off_t = 0x1000_0000;

#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    pad: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct Probe {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
    ops: [ProbeOp; PROBE_OPS],
}

const _: () = assert!(size_of::<Params>() == 120);
const _: () = assert!(size_of::<Sqe>() == 64);
const _: () = assert!(size_of::<Cqe>() == 16);
const _: () = assert!(size_of::<Probe>() == 16 + 8 * PROBE_OPS);

pub enum Request {
    Read {
        file: Rc<File>,
        offset: u64,
        buf: Buf,
    },
    Write {
        file: Rc<File>,
        offset: u64,
        buf: Buf,
    },
    SyncData {
        file: Rc<File>,
    },
}

#[derive(Debug)]
pub struct Done {
    pub id: u64,
    pub result: io::Result<usize>,
    pub buf: Option<Buf>,
}

struct Slot {
    id: u64,
    opcode: u8,
    offset: u64,
    file: Rc<File>,
    buf: Option<Buf>,
}

struct Map {
    ptr: NonNull<u8>,
    len: usize,
}

impl Map {
    #[allow(unsafe_code)]
    fn new(fd: &OwnedFd, len: usize, offset: libc::off_t) -> io::Result<Self> {
        // SAFETY: a new shared mapping of the ring descriptor; no existing memory is touched.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(ptr.cast()).ok_or_else(|| io::Error::other("null mapping"))?;
        Ok(Self { ptr, len })
    }

    fn at<T>(&self, offset: usize) -> *mut T {
        self.ptr.as_ptr().wrapping_add(offset).cast()
    }

    #[allow(unsafe_code)]
    fn read_u32(&self, offset: usize) -> u32 {
        // SAFETY: the offset comes from the kernel and points to an aligned u32 inside the mapping.
        unsafe { self.at::<u32>(offset).read() }
    }
}

impl Drop for Map {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the mapping was created by `Map::new` with this length and is not used after drop.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

pub struct Ring {
    queues: Map,
    sqes: Map,
    fd: OwnedFd,
    event: EventFd,
    sq_head: usize,
    sq_tail: usize,
    sq_mask: u32,
    cq_head: usize,
    cq_tail: usize,
    cq_mask: u32,
    cqes: usize,
    tail: u32,
    slots: Vec<Option<Slot>>,
    free: Vec<usize>,
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "io_uring lacks a required feature",
    )
}

fn check_long(result: libc::c_long) -> io::Result<libc::c_long> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn retryable(code: i32) -> bool {
    matches!(code, libc::EINTR | libc::EAGAIN | libc::EBUSY)
}

impl Ring {
    #[allow(unsafe_code)]
    pub fn new(entries: u32) -> io::Result<Self> {
        let mut params = Params::default();
        // SAFETY: `params` is a writable io_uring_params structure for the kernel to fill.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                libc::c_long::from(entries),
                &raw mut params,
            )
        };
        let fd = libc::c_int::try_from(check_long(fd)?).map_err(|_| unsupported())?;
        // SAFETY: `io_uring_setup` returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if params.features & (FEAT_SINGLE_MMAP | FEAT_NODROP) != FEAT_SINGLE_MMAP | FEAT_NODROP {
            return Err(unsupported());
        }
        probe(&fd)?;
        let sq_entries = params.sq_entries as usize;
        let sq_len = params.sq_off.array as usize + sq_entries * size_of::<u32>();
        let cq_len = params.cq_off.cqes as usize + params.cq_entries as usize * size_of::<Cqe>();
        let queues = Map::new(&fd, sq_len.max(cq_len), OFF_SQ_RING)?;
        let sqes = Map::new(&fd, sq_entries * size_of::<Sqe>(), OFF_SQES)?;
        let array = queues.at::<u32>(params.sq_off.array as usize);
        for index in 0..params.sq_entries {
            // SAFETY: the SQ array holds `sq_entries` u32 values inside the live mapping.
            unsafe { array.wrapping_add(index as usize).write(index) };
        }
        let event = EventFd::new()?;
        let event_fd = event.as_fd().as_raw_fd();
        // SAFETY: the argument points to one descriptor, matching the count of 1.
        let registered = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                libc::c_long::from(fd.as_raw_fd()),
                libc::c_long::from(REGISTER_EVENTFD),
                &raw const event_fd,
                libc::c_long::from(1u8),
            )
        };
        check_long(registered)?;
        let sq_mask = queues.read_u32(params.sq_off.ring_mask as usize);
        let cq_mask = queues.read_u32(params.cq_off.ring_mask as usize);
        let tail = queues.read_u32(params.sq_off.tail as usize);
        Ok(Self {
            queues,
            sqes,
            fd,
            event,
            sq_head: params.sq_off.head as usize,
            sq_tail: params.sq_off.tail as usize,
            sq_mask,
            cq_head: params.cq_off.head as usize,
            cq_tail: params.cq_off.tail as usize,
            cq_mask,
            cqes: params.cq_off.cqes as usize,
            tail,
            slots: (0..sq_entries).map(|_| None).collect(),
            free: (0..sq_entries).rev().collect(),
        })
    }

    pub fn event(&self) -> BorrowedFd<'_> {
        self.event.as_fd()
    }

    pub fn drain_event(&self) {
        self.event.drain();
    }

    pub fn idle(&self) -> bool {
        self.free.len() == self.slots.len()
    }

    pub fn queued(&self) -> u32 {
        let head = self.atomic(self.sq_head).load(Ordering::Acquire);
        self.tail.wrapping_sub(head)
    }

    pub fn push(&mut self, id: u64, request: Request) -> Result<(), Request> {
        let Some(index) = self.free.pop() else {
            return Err(request);
        };
        let slot = match request {
            Request::Read { file, offset, buf } => Slot {
                id,
                opcode: OP_READ,
                offset,
                file,
                buf: Some(buf),
            },
            Request::Write { file, offset, buf } => Slot {
                id,
                opcode: OP_WRITE,
                offset,
                file,
                buf: Some(buf),
            },
            Request::SyncData { file } => Slot {
                id,
                opcode: OP_FSYNC,
                offset: 0,
                file,
                buf: None,
            },
        };
        self.slots[index] = Some(slot);
        self.queue(index);
        Ok(())
    }

    pub fn submit(&mut self, out: &mut Vec<Done>) {
        let queued = self.queued();
        if queued == 0 {
            return;
        }
        if let Err(e) = self.enter(queued, 0, 0)
            && !e.raw_os_error().is_some_and(retryable)
        {
            self.retract(&e, out);
        }
    }

    pub fn complete(&mut self, out: &mut Vec<Done>) {
        let tail = self.atomic(self.cq_tail).load(Ordering::Acquire);
        let mut head = self.atomic(self.cq_head).load(Ordering::Relaxed);
        while head != tail {
            let cqe = self.cqe(head);
            head = head.wrapping_add(1);
            self.finish(cqe.user_data, cqe.res, out);
        }
        self.atomic(self.cq_head).store(head, Ordering::Release);
    }

    #[allow(unsafe_code)]
    fn queue(&mut self, index: usize) {
        let Some(slot) = self.slots[index].as_mut() else {
            return;
        };
        let mut sqe = Sqe {
            opcode: slot.opcode,
            fd: slot.file.as_raw_fd(),
            off: slot.offset,
            user_data: index as u64,
            ..Sqe::default()
        };
        match (slot.opcode, slot.buf.as_mut()) {
            (OP_READ, Some(buf)) => {
                let spare = buf.spare_mut();
                sqe.addr = spare.as_mut_ptr().expose_provenance() as u64;
                sqe.len = u32::try_from(spare.len()).unwrap_or(u32::MAX);
            }
            (OP_WRITE, Some(buf)) => {
                sqe.addr = buf.as_ptr().expose_provenance() as u64;
                sqe.len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            }
            _ => sqe.op_flags = FSYNC_DATASYNC,
        }
        let at = self
            .sqes
            .at::<Sqe>(0)
            .wrapping_add((self.tail & self.sq_mask) as usize);
        // SAFETY: at most `sq_entries` requests are outstanding, so the entry at the tail is not owned by the kernel, and it lies inside the live SQE mapping.
        unsafe { at.write(sqe) };
        self.tail = self.tail.wrapping_add(1);
        self.atomic(self.sq_tail)
            .store(self.tail, Ordering::Release);
    }

    #[allow(clippy::cast_sign_loss)]
    fn finish(&mut self, user_data: u64, res: i32, out: &mut Vec<Done>) {
        let Ok(index) = usize::try_from(user_data) else {
            return;
        };
        if res < 0 && retryable(-res) && self.slots.get(index).is_some_and(Option::is_some) {
            self.queue(index);
            return;
        }
        let Some(slot) = self.slots.get_mut(index).and_then(Option::take) else {
            return;
        };
        self.free.push(index);
        let result = if res < 0 {
            Err(io::Error::from_raw_os_error(-res))
        } else {
            Ok(res as usize)
        };
        let mut buf = slot.buf;
        if let (OP_READ, Some(buf), Ok(n)) = (slot.opcode, buf.as_mut(), &result) {
            buf.set_len(buf.len() + n);
        }
        out.push(Done {
            id: slot.id,
            result,
            buf,
        });
    }

    fn retract(&mut self, error: &io::Error, out: &mut Vec<Done>) {
        let head = self.atomic(self.sq_head).load(Ordering::Acquire);
        let mut at = head;
        while at != self.tail {
            let sqe = self.sqe(at);
            at = at.wrapping_add(1);
            let code = error.raw_os_error().unwrap_or(libc::EIO);
            self.finish(sqe.user_data, -code, out);
        }
        self.tail = head;
        self.atomic(self.sq_tail).store(head, Ordering::Release);
    }

    #[allow(unsafe_code)]
    fn enter(&self, submit: u32, wait: u32, flags: u32) -> io::Result<()> {
        // SAFETY: the descriptor is our ring and no argument pointer is passed.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                libc::c_long::from(self.fd.as_raw_fd()),
                libc::c_long::from(submit),
                libc::c_long::from(wait),
                libc::c_long::from(flags),
                ptr::null::<libc::c_void>(),
                libc::c_long::from(0u8),
            )
        };
        check_long(result).map(drop)
    }

    #[allow(unsafe_code)]
    fn atomic(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: the offset comes from the kernel and points to an aligned u32 inside the live ring mapping, which the kernel only accesses atomically.
        unsafe { AtomicU32::from_ptr(self.queues.at(offset)) }
    }

    #[allow(unsafe_code)]
    fn cqe(&self, position: u32) -> Cqe {
        let at = self
            .queues
            .at::<Cqe>(self.cqes)
            .wrapping_add((position & self.cq_mask) as usize);
        // SAFETY: the entry lies between the CQ head and the tail the kernel published, so the kernel has finished writing it, and it lies inside the live ring mapping.
        unsafe { at.read() }
    }

    #[allow(unsafe_code)]
    fn sqe(&self, position: u32) -> Sqe {
        let at = self
            .sqes
            .at::<Sqe>(0)
            .wrapping_add((position & self.sq_mask) as usize);
        // SAFETY: the entry lies between the SQ head and our tail, so the kernel has not taken it, and it lies inside the live SQE mapping.
        unsafe { at.read() }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        let mut out = Vec::new();
        loop {
            self.complete(&mut out);
            out.clear();
            if self.idle() {
                return;
            }
            let queued = self.queued();
            let used = self.slots.len() - self.free.len();
            let wait = u32::from(used > queued as usize);
            if let Err(e) = self.enter(queued, wait, ENTER_GETEVENTS)
                && !e.raw_os_error().is_some_and(retryable)
            {
                for slot in self.slots.drain(..).flatten() {
                    std::mem::forget(slot);
                }
                return;
            }
        }
    }
}

#[allow(unsafe_code)]
fn probe(fd: &OwnedFd) -> io::Result<()> {
    let mut probe = Probe {
        last_op: 0,
        ops_len: 0,
        resv: 0,
        resv2: [0; 3],
        ops: [ProbeOp::default(); PROBE_OPS],
    };
    // SAFETY: `probe` is writable with room for `PROBE_OPS` entries, matching the count.
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            libc::c_long::from(fd.as_raw_fd()),
            libc::c_long::from(REGISTER_PROBE),
            &raw mut probe,
            libc::c_long::try_from(PROBE_OPS).expect("fits"),
        )
    };
    check_long(result)?;
    for op in [OP_READ, OP_WRITE, OP_FSYNC] {
        let supported = op <= probe.last_op
            && probe
                .ops
                .get(usize::from(op))
                .is_some_and(|o| o.flags & OP_SUPPORTED != 0);
        if !supported {
            return Err(unsupported());
        }
    }
    Ok(())
}
