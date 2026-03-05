/*
 * CVE-2020-10065 Reproduction: Zephyr BT HCI-over-SPI Buffer Overflow
 *
 * Faithfully reproduces the vulnerable code path from Zephyr v2.7.0
 * drivers/bluetooth/hci/spi.c — function bt_spi_rx_thread().
 *
 * Original vulnerability: The SPI HCI driver reads Bluetooth packets
 * from an external radio chip (BlueNRG-MS) over SPI. Length fields in
 * incoming HCI headers are used directly in memcpy without bounds checks.
 *
 * Ground truth:
 *   - Source: SPI1_DR @ 0x4001300C — raw HCI packet bytes from BLE radio
 *   - Sink 1: COPY_SINK in bt_spi_rx_thread() [EVT path] —
 *             net_buf_add_mem with (rxmsg[EVT_HEADER_SIZE] + 2) unchecked,
 *             max 257 bytes into 76-byte buffer (CWE-787)
 *   - Sink 2: COPY_SINK in bt_spi_rx_thread() [ACL path] —
 *             net_buf_add_mem with acl_hdr.len (16-bit, max 65535) unchecked,
 *             into 76-byte buffer (CWE-787)
 *
 * Struct definitions and constants taken verbatim from Zephyr v2.7.0:
 *   include/bluetooth/hci.h — bt_hci_acl_hdr, bt_hci_evt_hdr
 *   drivers/bluetooth/hci/spi.c — packet type constants, header offsets
 *
 * CWE-787: Out-of-bounds Write
 * CVSS: 8.8 (NIST) / 3.8 (Zephyr)
 * Fixed in: Zephyr v3.0.0 (PR #41334, commit 9778f0cd)
 */
#include <stdint.h>
#include <string.h>

extern uint32_t __stack_top__;

void Reset_Handler(void);
void Default_Handler(void);
int main(void);

/* --- Vector table --- */
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[16] = {
    (uint32_t)&__stack_top__,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0, 0, 0, 0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

/* ═══════════════════════════════════════════════════════════════════════
 * STM32 SPI1 peripheral registers (source of attacker-controlled data)
 * ═══════════════════════════════════════════════════════════════════════ */
#define SPI1_BASE   0x40013000u
#define SPI1_CR1    (*(volatile uint32_t *)(SPI1_BASE + 0x00u))
#define SPI1_CR2    (*(volatile uint32_t *)(SPI1_BASE + 0x04u))
#define SPI1_SR     (*(volatile uint32_t *)(SPI1_BASE + 0x08u))
#define SPI1_DR     (*(volatile uint32_t *)(SPI1_BASE + 0x0Cu))

/* GPIO for IRQ pin from BLE radio chip */
#define GPIOA_BASE  0x40010800u
#define GPIOA_IDR   (*(volatile uint32_t *)(GPIOA_BASE + 0x08u))
#define IRQ_PIN_MASK (1u << 4)  /* PA4 = IRQ from BlueNRG */

/* ═══════════════════════════════════════════════════════════════════════
 * Zephyr HCI definitions (verbatim from include/bluetooth/hci.h v2.7.0)
 * ═══════════════════════════════════════════════════════════════════════ */
struct bt_hci_acl_hdr {
    uint16_t handle;
    uint16_t len;
} __attribute__((packed));

struct bt_hci_evt_hdr {
    uint8_t evt;
    uint8_t len;
} __attribute__((packed));

#define BT_HCI_ACL_HDR_SIZE  4
#define BT_HCI_EVT_HDR_SIZE  2

/* HCI packet type indicators (from spi.c) */
#define HCI_CMD  0x01
#define HCI_ACL  0x02
#define HCI_SCO  0x03
#define HCI_EVT  0x04

/* SPI protocol bytes */
#define SPI_WRITE  0x0A
#define SPI_READ   0x0B
#define READY_NOW  0x02

/* Header offsets (from spi.c) */
#define STATUS_HEADER_READY   0
#define STATUS_HEADER_TOREAD  3
#define PACKET_TYPE           0
#define EVT_HEADER_EVENT      1
#define EVT_HEADER_SIZE       2

/* Zephyr event codes used in the dispatch */
#define BT_HCI_EVT_VENDOR              0xFF
#define BT_HCI_EVT_LE_META_EVENT       0x3E
#define BT_HCI_EVT_LE_ADVERTISING_REPORT     0x02
#define BT_HCI_EVT_LE_EXT_ADVERTISING_REPORT 0x0D

/* ═══════════════════════════════════════════════════════════════════════
 * Minimal net_buf (reproduces Zephyr's fixed-size buffer allocation)
 *
 * Zephyr defaults:
 *   CONFIG_BT_RX_BUF_LEN     = 76  (for HCI events)
 *   CONFIG_BT_BUF_ACL_RX_SIZE = 27  (for ACL data)
 *
 * In practice both use the same net_buf pool; we use the larger size.
 * ═══════════════════════════════════════════════════════════════════════ */
#define NET_BUF_DATA_SIZE  76  /* CONFIG_BT_RX_BUF_LEN default */

struct net_buf {
    uint8_t  data[NET_BUF_DATA_SIZE];
    uint16_t len;
    uint8_t  type;
};

#define BT_BUF_ACL_IN  0x01
#define BT_BUF_EVT     0x02

/* Static buffer pool (simplified from Zephyr's net_buf_pool) */
static struct net_buf g_evt_buf;
static struct net_buf g_acl_buf;

/*
 * net_buf_add_mem — THE VULNERABLE FUNCTION
 *
 * In Zephyr, this does: memcpy(buf->data + buf->len, mem, len); buf->len += len;
 * The real Zephyr net_buf has an __ASSERT for tailroom, but asserts are
 * typically disabled in production builds (CONFIG_ASSERT=n).
 */
__attribute__((noinline))
static void *net_buf_add_mem(struct net_buf *buf, const void *mem, uint16_t len) {
    void *dst = &buf->data[buf->len];
    memcpy(dst, mem, len);  /* VULNERABLE: no bounds check against NET_BUF_DATA_SIZE */
    buf->len += len;
    return dst;
}

static struct net_buf *bt_buf_get_evt(uint8_t evt, int discardable, int timeout) {
    (void)evt; (void)discardable; (void)timeout;
    g_evt_buf.len = 0;
    g_evt_buf.type = BT_BUF_EVT;
    return &g_evt_buf;
}

static struct net_buf *bt_buf_get_rx(uint8_t type, int timeout) {
    (void)type; (void)timeout;
    g_acl_buf.len = 0;
    g_acl_buf.type = BT_BUF_ACL_IN;
    return &g_acl_buf;
}

__attribute__((noinline))
static void bt_recv(struct net_buf *buf) {
    /* Deliver buffer up the Bluetooth stack (stub) */
    (void)buf;
}

/* ═══════════════════════════════════════════════════════════════════════
 * SPI transceive — reads raw bytes from SPI peripheral
 *
 * In real Zephyr, this calls spi_transceive() which does full-duplex
 * SPI exchange. The underlying STM32 HAL reads SPI_DR for each byte.
 * ═══════════════════════════════════════════════════════════════════════ */
#define SPI_MAX_MSG_LEN  255  /* BlueNRG-MS max SPI message */

static uint8_t rxmsg[SPI_MAX_MSG_LEN];
static uint8_t txmsg[SPI_MAX_MSG_LEN];

__attribute__((noinline))
static int bt_spi_transceive(void *tx, uint32_t tx_len,
                             void *rx, uint32_t rx_len)
{
    (void)tx; (void)tx_len;
    uint8_t *dst = (uint8_t *)rx;
    for (uint32_t i = 0; i < rx_len; i++) {
        while (!(SPI1_SR & 0x01u)) {}        /* wait RXNE */
        dst[i] = (uint8_t)(SPI1_DR & 0xFFu); /* MMIO_READ: attacker data */
    }
    return 0;
}

static uint16_t sys_le16_to_cpu(uint16_t val) {
    /* ARM Cortex-M is little-endian, so this is identity */
    return val;
}

/* ═══════════════════════════════════════════════════════════════════════
 * bt_spi_rx_thread — VULNERABLE FUNCTION (verbatim logic from v2.7.0)
 *
 * This is the exact control flow from drivers/bluetooth/hci/spi.c.
 * Two sinks:
 *   1. HCI_EVT: net_buf_add_mem(buf, &rxmsg[1], rxmsg[EVT_HEADER_SIZE] + 2)
 *      → max 257 bytes into 76-byte buffer
 *   2. HCI_ACL: net_buf_add_mem(buf, &rxmsg[5], sys_le16_to_cpu(acl_hdr.len))
 *      → max 65535 bytes into 76-byte buffer
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void bt_spi_rx_thread(void)
{
    int discardable = 0;
    struct net_buf *buf;
    uint8_t header_master[5] = { SPI_READ, 0x00, 0x00, 0x00, 0x00 };
    uint8_t header_slave[5];
    struct bt_hci_acl_hdr acl_hdr;
    uint8_t size = 0U;
    int ret;

    (void)memset(txmsg, 0xFF, SPI_MAX_MSG_LEN);

    /* Main receive loop — in real Zephyr this runs as a kernel thread */
    while (1) {
        /* Wait for IRQ from radio chip (simplified: poll GPIO) */
        while (!(GPIOA_IDR & IRQ_PIN_MASK)) {}

        /* SPI header exchange: read 5-byte status from radio */
        ret = bt_spi_transceive(header_master, 5, header_slave, 5);

        size = header_slave[STATUS_HEADER_TOREAD];
        if (ret || size == 0) {
            continue;
        }

        /* SPI bulk read: read 'size' bytes of HCI packet */
        ret = bt_spi_transceive(txmsg, size, rxmsg, size);
        if (ret) {
            continue;
        }

        /* ── Packet type dispatch (verbatim from Zephyr v2.7.0) ── */
        switch (rxmsg[PACKET_TYPE]) {
        case HCI_EVT:
            if (rxmsg[EVT_HEADER_EVENT] == BT_HCI_EVT_VENDOR) {
                /* Vendor events skipped */
                continue;
            }

            discardable = 0;
            if (rxmsg[1] == BT_HCI_EVT_LE_META_EVENT &&
                (rxmsg[3] == BT_HCI_EVT_LE_ADVERTISING_REPORT ||
                 rxmsg[3] == BT_HCI_EVT_LE_EXT_ADVERTISING_REPORT)) {
                discardable = 1;
            }

            buf = bt_buf_get_evt(rxmsg[EVT_HEADER_EVENT], discardable, 0);
            if (!buf) {
                continue;
            }

            /*
             * ╔══════════════════════════════════════════════════════╗
             * ║  SINK 1 (CVE-2020-10065): HCI Event overflow       ║
             * ║                                                     ║
             * ║  rxmsg[EVT_HEADER_SIZE] = byte 2 of SPI data       ║
             * ║  Attacker controls this byte (0-255).               ║
             * ║  Total copy: up to 255 + 2 = 257 bytes             ║
             * ║  Buffer size: 76 bytes (NET_BUF_DATA_SIZE)          ║
             * ║  → heap buffer overflow of up to 181 bytes          ║
             * ╚══════════════════════════════════════════════════════╝
             */
            net_buf_add_mem(buf, &rxmsg[1],
                            rxmsg[EVT_HEADER_SIZE] + 2);
            break;

        case HCI_ACL:
            buf = bt_buf_get_rx(BT_BUF_ACL_IN, 0);

            memcpy(&acl_hdr, &rxmsg[1], sizeof(acl_hdr));
            net_buf_add_mem(buf, &acl_hdr, sizeof(acl_hdr));

            /*
             * ╔══════════════════════════════════════════════════════╗
             * ║  SINK 2 (CVE-2020-10065): HCI ACL overflow         ║
             * ║                                                     ║
             * ║  acl_hdr.len = 16-bit LE value from SPI data       ║
             * ║  Attacker controls this field (0-65535).            ║
             * ║  After 4-byte ACL header already added to buf,     ║
             * ║  remaining tailroom = 76 - 4 = 72 bytes.           ║
             * ║  → heap buffer overflow of up to 65463 bytes       ║
             * ╚══════════════════════════════════════════════════════╝
             */
            net_buf_add_mem(buf, &rxmsg[5],
                            sys_le16_to_cpu(acl_hdr.len));
            break;

        default:
            continue;
        }

        bt_recv(buf);
    }
}

/* ═══════════════════════════════════════════════════════════════════════ */

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    /* Enable SPI1 (simplified: just set SPE bit in CR1) */
    SPI1_CR1 = (1u << 6);  /* SPE = 1 */

    /* Run the vulnerable receive thread */
    bt_spi_rx_thread();

    return 0;
}
