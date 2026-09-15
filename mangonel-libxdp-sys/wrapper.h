/* The two public libxdp headers.
 *
 * xsk.h is the AF_XDP socket and UMEM side; libxdp.h is the program loader
 * that attaches an XDP program and populates its XSKMAP. Both pull in libbpf
 * and the kernel uapi headers, which the allowlist in build.rs filters back
 * out again.
 */
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
