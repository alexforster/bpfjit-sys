// src/lib.rs

use std::error::Error;
use std::ffi;
use std::mem;

use libc;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_insn_t {
    pub code: libc::c_ushort,
    pub jt: libc::c_uchar,
    pub jf: libc::c_uchar,
    pub k: libc::c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_program_t {
    pub bf_len: libc::c_uint,
    pub bf_insns: *mut bpf_insn_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_args_t {
    pub pkt: *const libc::c_uchar,
    pub wirelen: libc::size_t,
    pub buflen: libc::size_t,
    pub mem: *mut libc::c_uint,
    pub arg: *mut ffi::c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_ctx_t {
    pub copfuncs: *const ffi::c_void,
    pub nfuncs: libc::size_t,
    pub extwords: libc::size_t,
    pub preinited: libc::c_uint,
}

type bpfjit_func_t = Option<unsafe extern "C" fn(ctx: *const bpf_ctx_t, args: *mut bpf_args_t) -> libc::c_uint>;

#[link(name = "pcap")]
extern "C"
{
    #[link_name = "pcap_open_dead"]
    fn pcap_open_dead(linktype: libc::c_int, snaplen: libc::c_int) -> *mut ffi::c_void;

    #[link_name = "pcap_compile"]
    fn pcap_compile(p: *mut ffi::c_void, fp: *mut bpf_program_t, str: *const libc::c_char, optimize: libc::c_int, netmask: libc::c_uint) -> libc::c_int;

    #[link_name = "pcap_close"]
    fn pcap_close(p: *mut ffi::c_void);
}

extern "C"
{
    #[link_name = "bpfjit_generate_code"]
    fn bpfjit_generate_code(ctx: *const bpf_ctx_t, insns: *const bpf_insn_t, user: libc::size_t) -> bpfjit_func_t;

    #[link_name = "bpfjit_free_code"]
    fn bpfjit_free_code(func: bpfjit_func_t);
}

pub struct BpfJit
{
    ctx: *const bpf_ctx_t,
    cb: bpfjit_func_t,
}

impl BpfJit {
    pub fn new(filter: &str) -> Result<Self, Box<Error>>
    {
        unsafe {
            let mut result: BpfJit = mem::zeroed();

            let pcap = pcap_open_dead(1, 65535);
            let mut prog: bpf_program_t = mem::zeroed();
            let compiled = pcap_compile(pcap, &mut prog, ffi::CString::new(filter)?.as_ptr(), 1, 0xffffffff);
            pcap_close(pcap);

            if compiled != 0 {
                return Err(Box::from("could not compile cBPF expression"));
            }

            result.ctx = mem::zeroed();
            let jitted = bpfjit_generate_code(result.ctx, prog.bf_insns, prog.bf_len as libc::size_t);
            if jitted.is_none() {
                return Err(Box::from("could not JIT cBPF expression"));
            }

            result.cb = jitted;
            return Ok(result);
        }
    }

    pub fn matches(&self, data: &[u8]) -> bool
    {
        unsafe {
            let mut bpf_args: bpf_args_t = mem::zeroed();
            bpf_args.pkt = data.as_ptr();
            bpf_args.wirelen = data.len();
            bpf_args.buflen = data.len();

            let result = self.cb.unwrap()(self.ctx, &mut bpf_args);

            return result != 0;
        }
    }
}

impl Drop for BpfJit
{
    fn drop(&mut self)
    {
        unsafe {
            bpfjit_free_code(self.cb);
        }
    }
}
