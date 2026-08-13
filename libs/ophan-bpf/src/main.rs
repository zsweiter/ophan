#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::debug;

use crate::ingress_filter::errors::ErrorKind;

mod ingress_filter;

/// XDP program entry point. Classifies ingress packets against
/// the network policy defined in [`ingress_filter::classify_packet`].
#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match ingress_filter::classify_packet(&ctx) {
        Ok(result) => result,
        Err(err) => {
            debug!(&ctx, "packet error: {}", err.description());

            match err {
                ErrorKind::InvalidEtherType(_) => xdp_action::XDP_PASS,
                _ => xdp_action::XDP_PASS,
            }
        },
    }
}

// Panic handler required for `#![no_std]` eBPF targets.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
