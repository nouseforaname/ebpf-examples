#![no_std]
#![no_main]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod vmlinux;

use core::ffi::CStr;

use aya_ebpf::{
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
    //let dpd: c_int = ctx.arg(0).ok_or(666i64)?;
    let file: *const filename = ctx.arg(1).ok_or(667i64)?;

    info!(&ctx, "probing");
    return unsafe {
        match bpf_probe_read_kernel(file) {
            Ok(file) => {
                let mut bytes = [0u8; 128];
                info!(&ctx, "reading filename");
                let f_name_str = core::str::from_utf8_unchecked(
                    match bpf_probe_read_kernel_str_bytes(file.name as *const u8, &mut bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            info!(&ctx, "failed read str {}", e);
                            Err(1)?
                        }
                    }, //  .map_err(|_| -1)?,
                );
                info!(&ctx, "called: {}", f_name_str);
                Ok(1)
            }
            Err(e) => {
                info!(&ctx, "failed {}", e);
                Err(-1)
            }
        }
    };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
