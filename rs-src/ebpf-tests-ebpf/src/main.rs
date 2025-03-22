#![no_std]
#![no_main]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod vmlinux;

use aya_ebpf::{
    cty::c_int,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::kprobe,
    programs::ProbeContext,
};

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 4096],
}

use aya_log_ebpf::info;
use vmlinux::filename;

#[kprobe]
pub fn ebpf_tests(ctx: ProbeContext) -> i64 {
    match try_ebpf_tests(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ebpf_tests(ctx: ProbeContext) -> Result<i64, i64> {
    let dpd: c_int = ctx.arg(0).ok_or(666i64)?;
    let file: *const filename = ctx.arg(1).ok_or(667i64)?;
    unsafe {
        match bpf_probe_read_kernel(file) {
            Ok(file) => {
                let buf = &mut [0u8; 128];
                bpf_probe_read_kernel_str_bytes(file.name as *const u8, buf).map_err(|_| -1)?;
                let path = core::str::from_utf8_unchecked(buf);
                info!(&ctx, "del on {}:{}", dpd, path);
                return Ok(1);
            }
            _ => Err(-1),
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
