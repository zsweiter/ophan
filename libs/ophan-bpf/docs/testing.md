## Black-Box Testing Infrastructure in Aya: `TestRunOptions` and `TestRunAttrs`

The Linux kernel provides the `BPF_PROG_TEST_RUN` syscall interface (historically known as `BPF_PROG_RUN`), which allows executing loaded eBPF programs against synthetic memory buffers in kernel space, without the need to bind the program to a real physical network interface or inject traffic onto the wire.

The Aya library in Rust exposes this kernel API through the `TestRunOptions` structure and the `test_run()` method available in eBPF program abstractions such as `Xdp`.

### Technical Analysis of the `TestRunOptions` Parameter

The `TestRunOptions<'a>` structure manages the input/output buffers and execution attributes in the kernel:

```rust
pub struct TestRunOptions<'a> {
    pub data_in: Option<&'a [u8]>,
    pub data_out: Option<&'a mut [u8]>,
    pub ctx_in: Option<&'a [u8]>,
    pub ctx_out: Option<&'a mut [u8]>,
    pub repeat: u32,
    pub attrs: TestRunAttrs,
}
```

- **`data_in`**: Reference to a byte slice (`&[u8]`) representing the raw network frame constructed synthetically. It maps directly to the `data` and `data_end` pointers received by the `xdp_buff` structure inside the kernel.
- **`data_out`**: Optional mutable buffer where the kernel will copy the packet content after the eBPF program execution. This is critical for testing XDP programs that modify packets in place (in-place modification), such as routing, GRE/VXLAN tunnel decapsulation, or MAC/IP address rewriting (`XDP_TX` or `XDP_REDIRECT`).
- **`ctx_in`**: Optional buffer that allows passing a custom context structure (`xdp_md`) to the eBPF program. In XDP programs, it allows defining input attributes such as the incoming network interface index (`rx_queue_index` or `ingress_ifindex`).
- **`ctx_out`**: Optional buffer where the kernel writes back the `xdp_md` context modified by the eBPF execution.
- **`repeat`**: Test repetition counter within the kernel. If set to a value greater than 1 (for example, `10000`), the kernel executes the eBPF program in a closed loop over the same input data. This allows measuring average execution latency in nanoseconds and validating filter throughput.
- **`attrs`**: Instance of the `TestRunAttrs` structure that controls the parameters of the kernel's batched execution subsystem.

### Technical Analysis of the `TestRunAttrs` Parameter

The `TestRunAttrs` structure contains the kernel-side execution configuration:

```rust
pub struct TestRunAttrs {
    pub(crate) batch_size: u32,
    pub(crate) flags: u32,
}
```

- **`batch_size`**: Specifies the batch size used by the kernel during repeated execution of the XDP test. It allows simulating the behavior of network drivers that process packet bursts via NAPI (_New API_).
- **`flags`**: Bitmask that configures specific kernel modifiers for the test program execution.

| **Field in Aya Struct** | **Kernel Syscall Equivalent (bpf_attr)** | **Purpose in Black-Box Testing**                                              |
| ----------------------- | ---------------------------------------- | ----------------------------------------------------------------------------- |
| `data_in`               | `test.data_in`                           | Injection of synthetic frames (valid, malformed, attack).                     |
| `data_out`              | `test.data_out`                          | Verification of byte transformations after `XDP_TX` / `XDP_REDIRECT` actions. |
| `ctx_in`                | `test.ctx_in`                            | Test isolation by defining metrics such as `ingress_ifindex`.                 |
| `repeat`                | `test.repeat`                            | Performance regression testing and latency benchmarking.                      |
| `attrs.batch_size`      | `test.batch_size`                        | Simulation of NIC NAPI bursts.                                                |
| `attrs.flags`           | `test.flags`                             | Control of advanced `BPF_PROG_TEST_RUN` execution flags.                      |

## Practical Implementation of Synthetic Frame Generation in Rust

To structure the black-box test suite, a Rust archetype is developed that manually composes byte arrays to represent test frames and invokes the eBPF program execution through Aya.

```rust
#[cfg(test)]
mod xdp_blackbox_suite {
    use aya::{
        programs::{Xdp, TestRunOptions, TestRunAttrs},
        Ebpf,
    };
    use std::convert::TryInto;

    // Return constants for kernel XDP actions
    const XDP_ABORTED: u32 = 0;
    const XDP_DROP: u32 = 1;
    const XDP_PASS: u32 = 2;
    const XDP_TX: u32 = 3;
    const XDP_REDIRECT: u32 = 4;

    /// Builds a legitimate IPv4/UDP frame with VLAN Tagging (IEEE 802.1Q)
    fn generate_valid_vlan_udp_frame() -> Vec<u8> {
        let mut frame = Vec::with_capacity(64);

        // --- Ethernet Header (14 base bytes) ---
        frame.extend_from_slice(&[0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]); // Destination MAC
        frame.extend_from_slice(&[0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC]); // Source MAC
        frame.extend_from_slice(&[0x81, 0x00]);                         // TPID: IEEE 802.1Q

        // --- 802.1Q VLAN tag (2 bytes) + EtherType (2 bytes) ---
        frame.extend_from_slice(&[0x00, 0x64]);                         // TCI: Priority 0, VID 100 (0x064)
        frame.extend_from_slice(&[0x08, 0x00]);                         // Encapsulated EtherType: IPv4

        // --- IPv4 Header (20 bytes) ---
        frame.push(0x45);                                               // Version 4, IHL 5 (20 bytes)
        frame.push(0x00);                                               // DSCP / ECN
        frame.extend_from_slice(&[0x00, 0x20]);                         // Total Length: 32 bytes (20 IP + 8 UDP + 4 Data)
        frame.extend_from_slice(&[0x1A, 0x2C]);                         // Identification
        frame.extend_from_slice(&[0x40, 0x00]);                         // Flags: Don't Fragment (DF = 1)
        frame.push(0x40);                                               // Time to Live (TTL = 64)
        frame.push(0x17);                                               // Protocol: UDP (17 / 0x17)
        frame.extend_from_slice(&[0x00, 0x00]);                         // Checksum (simplified for testing)
        frame.extend_from_slice(&[192, 168, 1, 50]);                    // Source IP: 192.168.1.50
        frame.extend_from_slice(&[10, 0, 0, 1]);                        // Destination IP: 10.0.0.1

        // --- UDP Header (8 bytes) ---
        frame.extend_from_slice(&[0x1F, 0x90]);                         // Source Port: 8080
        frame.extend_from_slice(&[0x00, 0x35]);                         // Destination Port: 53 (DNS)
        frame.extend_from_slice(&[0x00, 0x0C]);                         // UDP Length: 12 bytes
        frame.extend_from_slice(&[0x00, 0x00]);                         // Checksum

        // Payload
        frame.extend_from_slice(b"PING");

        frame
    }

    /// Builds a malicious TCP Xmas Scan frame over IPv4
    fn generate_tcp_xmas_attack_frame() -> Vec<u8> {
        let mut frame = Vec::with_capacity(54);

        // Ethernet (14 bytes)
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);                         // IPv4

        // IPv4 (20 bytes)
        frame.push(0x45);                                               // IHL = 5
        frame.push(0x00);
        frame.extend_from_slice(&[0x00, 0x28]);                         // Total Length: 40 bytes
        frame.extend_from_slice(&[0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.push(0x40);
        frame.push(0x06);                                               // Protocol: TCP (6)
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[10, 0, 0, 66]);
        frame.extend_from_slice(&[10, 0, 0, 1]);

        // TCP header with anomalous Xmas flags (20 bytes)
        frame.extend_from_slice(&[0x04, 0xD2]);                         // Source Port: 1234
        frame.extend_from_slice(&[0x00, 0x50]);                         // Destination Port: 80
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);             // Sequence Number
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);             // Acknowledgment Number
        frame.push(0x50);                                               // Data Offset: 5 (20 bytes)
        frame.push(0x29);                                               // TCP Flags: URG (0x20) + PSH (0x08) + FIN (0x01) = 0x29
        frame.extend_from_slice(&[0x10, 0x00]);                         // Window Size
        frame.extend_from_slice(&[0x00, 0x00]);                         // Checksum
        frame.extend_from_slice(&[0x00, 0x00]);                         // Urgent Pointer

        frame
    }

    #[test]
    fn test_blackbox_xdp_filter() -> Result<(), Box<dyn std::error::Error>> {
        // Load compiled eBPF object
        let mut ebpf = Ebpf::load_file("target/bpfel-unknown-none/release/my_xdp_filter")?;

        let program: &mut Xdp = ebpf.program_mut("filter_xdp").unwrap().try_into()?;
        program.load()?;

        // --- Test Case 1: Valid VLAN + UDP frame ---
        let valid_frame = generate_valid_vlan_udp_frame();
        let mut output_buffer = vec![0u8; 1518];

        let opts_valid = TestRunOptions {
            data_in: Some(&valid_frame),
            data_out: Some(&mut output_buffer),
            ctx_in: None,
            ctx_out: None,
            repeat: 1,
            attrs: TestRunAttrs {
                batch_size: 1,
                flags: 0,
            },
        };

        let result_valid = program.test_run(opts_valid)?;
        assert_eq!(result_valid.return_value, XDP_PASS, "The valid VLAN+UDP frame must return XDP_PASS");

        // --- Test Case 2: TCP Xmas Scan attack ---
        let xmas_frame = generate_tcp_xmas_attack_frame();

        let opts_xmas = TestRunOptions {
            data_in: Some(&xmas_frame),
            data_out: None,
            ctx_in: None,
            ctx_out: None,
            repeat: 1,
            attrs: TestRunAttrs {
                batch_size: 1,
                flags: 0,
            },
        };

        let result_xmas = program.test_run(opts_xmas)?;
        assert_eq!(result_xmas.return_value, XDP_DROP, "The TCP Xmas Scan attack must be dropped with XDP_DROP");

        Ok(())
    }
}
```
