// src/lib.rs

#![allow(non_camel_case_types)]

use std::error;
use std::ffi;
use std::mem;
use std::str::FromStr;
use std::sync;

use lazy_static::lazy_static;
use libc::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_insn_t {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
}

#[repr(C)]
#[derive(Debug)]
struct bpf_program_t {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn_t,
}

#[repr(C)]
#[derive(Debug)]
struct bpf_args_t {
    pub pkt: *const c_uchar,
    pub wirelen: size_t,
    pub buflen: size_t,
    pub mem: *mut c_uint,
    pub arg: *mut ffi::c_void,
}

#[repr(C)]
#[derive(Debug)]
struct bpf_ctx_t {
    pub copfuncs: *const ffi::c_void,
    pub nfuncs: size_t,
    pub extwords: size_t,
    pub preinited: c_uint,
}

type bpfjit_func_t = unsafe extern "C" fn(ctx: *const bpf_ctx_t, args: *mut bpf_args_t) -> c_uint;

#[link(name = "pcap")]
extern "C" {
    fn pcap_open_dead(linktype: c_int, snaplen: c_int) -> *mut ffi::c_void;

    fn pcap_compile(
        p: *mut ffi::c_void,
        fp: *mut bpf_program_t,
        str: *const c_char,
        optimize: c_int,
        netmask: c_uint,
    ) -> c_int;

    fn pcap_close(p: *mut ffi::c_void);

    fn pcap_freecode(fp: *mut bpf_program_t);

    fn pcap_geterr(p: *mut ffi::c_void) -> *const c_char;
}

extern "C" {
    fn bpfjit_generate_code(ctx: *const bpf_ctx_t, insns: *const bpf_insn_t, user: size_t) -> Option<bpfjit_func_t>;

    fn bpfjit_free_code(func: bpfjit_func_t);
}

lazy_static! {
    static ref BIGLOCK: sync::Mutex<()> = sync::Mutex::new(());
}

unsafe fn compile(filter: &str, linktype: c_int, snaplen: c_int) -> Result<Vec<Opcode>, Box<dyn error::Error>> {
    let mut bpf_program: bpf_program_t = mem::zeroed();

    let lock = BIGLOCK.lock().unwrap(); // pcap_compile() in libpcap <1.8 is not thread safe

    let pcap = pcap_open_dead(linktype, snaplen);

    let compiled = pcap_compile(
        pcap,
        &mut bpf_program,
        ffi::CString::new(filter)?.as_ptr(),
        1,
        0xffff_ffff, // PCAP_NETMASK_UNKNOWN
    );

    if compiled != 0 {
        return Err(Box::from(format!(
            "could not compile cBPF expression: {}",
            ffi::CStr::from_ptr(pcap_geterr(pcap)).to_str().unwrap()
        )));
    }

    pcap_close(pcap);

    drop(lock);

    let mut result: Vec<Opcode> = vec![];

    for i in 0isize..(bpf_program.bf_len as isize) {
        let insn = *bpf_program.bf_insns.offset(i);
        result.push(insn.into());
    }

    pcap_freecode(&mut bpf_program);

    Ok(result)
}

unsafe fn jit(program: &bpf_program_t) -> Result<(bpf_ctx_t, bpfjit_func_t), Box<dyn error::Error>> {
    let ctx: bpf_ctx_t = mem::zeroed();
    let cb = bpfjit_generate_code(&ctx, program.bf_insns, program.bf_len as size_t);
    match cb {
        Some(cb) => Ok((ctx, cb)),
        None => Err(Box::from("could not JIT cBPF bytecode")),
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Opcode(pub u16, pub u8, pub u8, pub u32);

impl From<bpf_insn_t> for Opcode {
    fn from(insn: bpf_insn_t) -> Self {
        Opcode(insn.code, insn.jt, insn.jf, insn.k)
    }
}

impl FromStr for Opcode {
    type Err = Box<dyn error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_ascii_whitespace().collect();
        if parts.len() != 4 {
            return Err("'s' must be 4 numbers separated by whitespace".into());
        }
        let code: u16 = parts[0].parse::<u16>()?;
        let jt: u8 = parts[1].parse::<u8>()?;
        let jf: u8 = parts[2].parse::<u8>()?;
        let k: u32 = parts[3].parse::<u32>()?;
        Ok(Opcode(code, jt, jf, k))
    }
}

impl From<Vec<Opcode>> for bpf_program_t {
    fn from(opcodes: Vec<Opcode>) -> Self {
        let mut insns = vec![];
        for opcode in opcodes {
            insns.push(bpf_insn_t { code: opcode.0, jt: opcode.1, jf: opcode.2, k: opcode.3 });
        }
        let bf_len = insns.len() as c_uint;
        let bf_insns = insns.as_mut_ptr();
        mem::forget(insns);
        bpf_program_t { bf_len, bf_insns }
    }
}

pub enum Linktype {
    Other(i32),
    Ethernet,
    Ip,
}

impl From<Linktype> for c_int {
    fn from(linktype: Linktype) -> Self {
        match linktype {
            Linktype::Other(linktype) => linktype as c_int,
            Linktype::Ethernet => 1,
            Linktype::Ip => 12,
        }
    }
}

pub struct BpfJit {
    prog: Vec<Opcode>,
    ctx: bpf_ctx_t,
    cb: bpfjit_func_t,
}

impl BpfJit {
    pub fn new(filter: &str, linktype: Linktype) -> Result<Self, Box<dyn error::Error>> {
        unsafe {
            let prog = compile(filter, linktype.into(), 0xFFFF)?;
            let (ctx, cb) = jit(&prog.clone().into())?;
            Ok(BpfJit { prog, ctx, cb })
        }
    }

    pub fn raw(opcodes: &[Opcode]) -> Result<Self, Box<dyn error::Error>> {
        unsafe {
            let prog = opcodes.to_vec();
            let (ctx, cb) = jit(&prog.clone().into())?;
            Ok(BpfJit { prog, ctx, cb })
        }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        unsafe {
            let mut bpf_args: bpf_args_t = mem::zeroed();
            bpf_args.pkt = data.as_ptr();
            bpf_args.wirelen = data.len();
            bpf_args.buflen = data.len();
            (self.cb)(&self.ctx, &mut bpf_args)
        }
    }
}

impl Clone for BpfJit {
    fn clone(&self) -> Self {
        unsafe {
            let prog = self.prog.clone();
            let (ctx, cb) = jit(&prog.clone().into()).unwrap();
            BpfJit { prog, ctx, cb }
        }
    }
}

impl Drop for BpfJit {
    fn drop(&mut self) {
        unsafe {
            bpfjit_free_code(self.cb);
        }
    }
}

unsafe impl Send for BpfJit {}
unsafe impl Sync for BpfJit {}
