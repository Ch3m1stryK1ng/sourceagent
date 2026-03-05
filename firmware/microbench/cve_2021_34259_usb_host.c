/*
 * CVE-2021-34259 (+ CVE-2021-42553, CVE-2021-34262) Reproduction:
 * STM32 USB Host Library — Descriptor Parsing Buffer Overflows
 *
 * Faithfully reproduces the vulnerable code path from STM32CubeH7 v1.8.0
 * Middlewares/ST/STM32_USB_Host_Library/Core/Src/usbh_ctlreq.c
 *
 * Original vulnerability: USB Host reads configuration descriptors from an
 * untrusted USB device. Multiple fields are used without validation:
 *   - wTotalLength controls parsing loop bound (CVE-2021-34259)
 *   - bNumEndpoints controls endpoint parsing count (CVE-2021-42553)
 *   - wMaxPacketSize used unvalidated downstream (CVE-2021-34262)
 *
 * Ground truth:
 *   - Source: USB_OTG_FS FIFO @ 0x50001000 — raw USB descriptor bytes
 *   - Sink 1: USBH_ParseCfgDesc() — wTotalLength (16-bit) controls loop
 *             that walks past CfgDesc_Raw[512] buffer (CVE-2021-34259)
 *   - Sink 2: USBH_ParseInterfaceDesc() — bNumEndpoints not clamped to
 *             USBH_MAX_NUM_ENDPOINTS, overflows Ep_Desc[] (CVE-2021-42553)
 *   - Sink 3: USBH_ParseEPDesc() — wMaxPacketSize unchecked, stored into
 *             struct and used for transfer sizes downstream (CVE-2021-34262)
 *
 * Struct definitions from usbh_def.h v1.8.0.
 * Function logic from usbh_ctlreq.c v1.8.0.
 *
 * CWE-120: Buffer Copy without Checking Size of Input
 * CVSS: 6.8 (Physical access, no auth)
 * Fixed in: STM32CubeH7 v1.10.0 (March 2022)
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
 * STM32 USB OTG FS peripheral (source of attacker-controlled data)
 *
 * USB_OTG_FS_BASE = 0x50000000 (STM32F4/F7/H7)
 * GRXSTSP = base + 0x020 (RX Status Pop register)
 * FIFO    = base + 0x1000 (Data FIFO for EP0)
 * ═══════════════════════════════════════════════════════════════════════ */
#define USB_OTG_FS_BASE     0x50000000u
#define USB_OTG_GRXSTSP     (*(volatile uint32_t *)(USB_OTG_FS_BASE + 0x020u))
#define USB_OTG_FIFO_EP0    (*(volatile uint32_t *)(USB_OTG_FS_BASE + 0x1000u))

/* ═══════════════════════════════════════════════════════════════════════
 * USB Descriptor type constants (from USB 2.0 spec)
 * ═══════════════════════════════════════════════════════════════════════ */
#define USB_DESC_TYPE_DEVICE         0x01u
#define USB_DESC_TYPE_CONFIGURATION  0x02u
#define USB_DESC_TYPE_INTERFACE      0x04u
#define USB_DESC_TYPE_ENDPOINT       0x05u

#define USB_LEN_CFG_DESC             9u
#define USB_CONFIGURATION_DESC_SIZE  9u
#define USB_INTERFACE_DESC_SIZE      9u
#define USB_ENDPOINT_DESC_SIZE       7u

/* ═══════════════════════════════════════════════════════════════════════
 * STM32 USB Host Library struct definitions
 * (verbatim from usbh_def.h v1.8.0)
 * ═══════════════════════════════════════════════════════════════════════ */
#define USBH_MAX_NUM_ENDPOINTS       2u
#define USBH_MAX_NUM_INTERFACES      2u
#define USBH_MAX_SIZE_CONFIGURATION  0x200u  /* 512 bytes */
#define USBH_MAX_DATA_BUFFER         0x200u
#define USBH_MAX_EP_PACKET_SIZE      0x400u  /* 1024 bytes */

/* Descriptor header — used by USBH_GetNextDesc to walk the chain */
typedef struct {
    uint8_t bLength;
    uint8_t bDescriptorType;
} USBH_DescHeader_t;

/* Endpoint Descriptor */
typedef struct {
    uint8_t   bLength;
    uint8_t   bDescriptorType;
    uint8_t   bEndpointAddress;
    uint8_t   bmAttributes;
    uint16_t  wMaxPacketSize;   /* CVE-2021-34262: not validated */
    uint8_t   bInterval;        /* CVE-2021-34262: not validated */
} __attribute__((packed)) USBH_EpDescTypeDef;

/* Interface Descriptor — note embedded Ep_Desc array */
typedef struct {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint8_t  bInterfaceNumber;
    uint8_t  bAlternateSetting;
    uint8_t  bNumEndpoints;     /* CVE-2021-42553: not clamped */
    uint8_t  bInterfaceClass;
    uint8_t  bInterfaceSubClass;
    uint8_t  bInterfaceProtocol;
    uint8_t  iInterface;
    USBH_EpDescTypeDef Ep_Desc[USBH_MAX_NUM_ENDPOINTS];  /* overflow target */
} USBH_InterfaceDescTypeDef;

/* Configuration Descriptor — top-level parsed structure */
typedef struct {
    uint8_t   bLength;
    uint8_t   bDescriptorType;
    uint16_t  wTotalLength;     /* CVE-2021-34259: not validated */
    uint8_t   bNumInterfaces;
    uint8_t   bConfigurationValue;
    uint8_t   iConfiguration;
    uint8_t   bmAttributes;
    uint8_t   bMaxPower;
    USBH_InterfaceDescTypeDef Itf_Desc[USBH_MAX_NUM_INTERFACES];
} USBH_CfgDescTypeDef;

/* Device Descriptor */
typedef struct {
    uint8_t   bLength;
    uint8_t   bDescriptorType;
    uint16_t  bcdUSB;
    uint8_t   bDeviceClass;
    uint8_t   bDeviceSubClass;
    uint8_t   bDeviceProtocol;
    uint8_t   bMaxPacketSize;   /* CVE-2021-34268: not validated */
    uint16_t  idVendor;
    uint16_t  idProduct;
    uint16_t  bcdDevice;
    uint8_t   iManufacturer;
    uint8_t   iProduct;
    uint8_t   iSerialNumber;
    uint8_t   bNumConfigurations;
} __attribute__((packed)) USBH_DevDescTypeDef;

/* Simplified host handle */
typedef struct {
    USBH_DevDescTypeDef  DevDesc;
    USBH_CfgDescTypeDef  CfgDesc;
    uint8_t              CfgDesc_Raw[USBH_MAX_SIZE_CONFIGURATION];
} USBH_DeviceTypeDef;

typedef struct {
    USBH_DeviceTypeDef device;
} USBH_HandleTypeDef;

/* ═══════════════════════════════════════════════════════════════════════
 * LE16 macro (verbatim from STM32 USB library)
 * ═══════════════════════════════════════════════════════════════════════ */
#define LE16(addr)  (((uint16_t)(addr)[1] << 8) | (uint16_t)(addr)[0])

/* ═══════════════════════════════════════════════════════════════════════
 * USB FIFO read — reads raw bytes from USB OTG FIFO
 * In real STM32 HAL, USB_ReadPacket reads 32-bit words from FIFO register
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void USB_ReadPacket(uint8_t *dest, uint16_t len)
{
    uint32_t count32 = ((uint32_t)len + 3u) / 4u;
    uint32_t *dest32 = (uint32_t *)(void *)dest;
    for (uint32_t i = 0; i < count32; i++) {
        dest32[i] = USB_OTG_FIFO_EP0;  /* MMIO_READ: attacker-controlled */
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * USBH_GetNextDesc — walks descriptor chain
 * (verbatim from usbh_ctlreq.c v1.8.0)
 *
 * Note: if bLength == 0, this never advances → infinite loop (Bug 11)
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static USBH_DescHeader_t *USBH_GetNextDesc(uint8_t *pbuf, uint16_t *ptr)
{
    USBH_DescHeader_t *pnext;

    *ptr += ((USBH_DescHeader_t *)(void *)pbuf)->bLength;
    pnext = (USBH_DescHeader_t *)(void *)((uint8_t *)(void *)pbuf +
             ((USBH_DescHeader_t *)(void *)pbuf)->bLength);

    return pnext;
}

/* ═══════════════════════════════════════════════════════════════════════
 * USBH_ParseEPDesc — parse endpoint descriptor
 * (verbatim from usbh_ctlreq.c v1.8.0)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 3 (CVE-2021-34262): wMaxPacketSize not validated         ║
 * ║                                                                ║
 * ║  Attacker provides wMaxPacketSize up to 0xFFFF in descriptor.  ║
 * ║  Value stored in Ep_Desc and used for DMA transfer sizes       ║
 * ║  downstream → buffer overflow during actual data transfers.    ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void USBH_ParseEPDesc(USBH_EpDescTypeDef *ep_descriptor,
                              uint8_t *buf)
{
    ep_descriptor->bLength          = *(uint8_t *)(buf + 0);
    ep_descriptor->bDescriptorType  = *(uint8_t *)(buf + 1);
    ep_descriptor->bEndpointAddress = *(uint8_t *)(buf + 2);
    ep_descriptor->bmAttributes     = *(uint8_t *)(buf + 3);
    ep_descriptor->wMaxPacketSize   = LE16(buf + 4);  /* SINK: unvalidated */
    ep_descriptor->bInterval        = *(uint8_t *)(buf + 6);
}

/* ═══════════════════════════════════════════════════════════════════════
 * USBH_ParseInterfaceDesc — parse interface descriptor
 * (verbatim from usbh_ctlreq.c v1.8.0)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 2 (CVE-2021-42553): bNumEndpoints not clamped            ║
 * ║                                                                ║
 * ║  Attacker provides bNumEndpoints > USBH_MAX_NUM_ENDPOINTS.    ║
 * ║  The endpoint parsing loop in USBH_ParseCfgDesc() writes      ║
 * ║  past Ep_Desc[2] array into adjacent struct memory.            ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void USBH_ParseInterfaceDesc(USBH_InterfaceDescTypeDef *if_descriptor,
                                     uint8_t *buf)
{
    if_descriptor->bLength            = *(uint8_t *)(buf + 0);
    if_descriptor->bDescriptorType    = *(uint8_t *)(buf + 1);
    if_descriptor->bInterfaceNumber   = *(uint8_t *)(buf + 2);
    if_descriptor->bAlternateSetting  = *(uint8_t *)(buf + 3);
    if_descriptor->bNumEndpoints      = *(uint8_t *)(buf + 4); /* SINK: unclamped */
    if_descriptor->bInterfaceClass    = *(uint8_t *)(buf + 5);
    if_descriptor->bInterfaceSubClass = *(uint8_t *)(buf + 6);
    if_descriptor->bInterfaceProtocol = *(uint8_t *)(buf + 7);
    if_descriptor->iInterface         = *(uint8_t *)(buf + 8);
}

/* ═══════════════════════════════════════════════════════════════════════
 * USBH_ParseCfgDesc — THE MAIN VULNERABLE FUNCTION
 * (verbatim logic from usbh_ctlreq.c v1.8.0)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 1 (CVE-2021-34259): wTotalLength not validated           ║
 * ║                                                                ║
 * ║  cfg_desc->wTotalLength = LE16(buf + 2) — raw from device.    ║
 * ║  Attacker sends wTotalLength = 0xFFFF in config descriptor.    ║
 * ║  Parsing loop walks past CfgDesc_Raw[512] buffer.              ║
 * ║  USBH_GetNextDesc reads arbitrary memory as descriptors.       ║
 * ║  Parsed data written into cfg_desc struct → memory corruption. ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void USBH_ParseCfgDesc(USBH_CfgDescTypeDef *cfg_desc,
                               uint8_t *buf, uint16_t length)
{
    USBH_InterfaceDescTypeDef *pif;
    USBH_EpDescTypeDef        *pep;
    USBH_DescHeader_t         *pdesc = (USBH_DescHeader_t *)(void *)buf;
    uint16_t                   ptr;
    uint8_t                    if_ix = 0u;
    uint8_t                    ep_ix = 0u;

    /* Parse configuration descriptor header */
    cfg_desc->bLength             = *(uint8_t *)(buf + 0);
    cfg_desc->bDescriptorType     = *(uint8_t *)(buf + 1);
    cfg_desc->wTotalLength        = LE16(buf + 2);         /* BUG: no MIN() */
    cfg_desc->bNumInterfaces      = *(uint8_t *)(buf + 4);
    cfg_desc->bConfigurationValue = *(uint8_t *)(buf + 5);
    cfg_desc->iConfiguration      = *(uint8_t *)(buf + 6);
    cfg_desc->bmAttributes        = *(uint8_t *)(buf + 7);
    cfg_desc->bMaxPower           = *(uint8_t *)(buf + 8);

    if (length > USB_CONFIGURATION_DESC_SIZE)
    {
        ptr = USB_LEN_CFG_DESC;
        pif = (USBH_InterfaceDescTypeDef *)0;

        /*
         * Outer loop: walk descriptors using wTotalLength as bound.
         * wTotalLength is attacker-controlled, can be >> 512.
         * pdesc walks past CfgDesc_Raw buffer boundary.
         */
        while ((if_ix < USBH_MAX_NUM_INTERFACES) &&
               (ptr < cfg_desc->wTotalLength))          /* CVE-2021-34259 */
        {
            pdesc = USBH_GetNextDesc((uint8_t *)(void *)pdesc, &ptr);

            if (pdesc->bDescriptorType == USB_DESC_TYPE_INTERFACE)
            {
                if (if_ix < USBH_MAX_NUM_INTERFACES) {
                    pif = &cfg_desc->Itf_Desc[if_ix];
                } else {
                    pif = (USBH_InterfaceDescTypeDef *)0;
                }

                if (pif != (USBH_InterfaceDescTypeDef *)0) {
                    USBH_ParseInterfaceDesc(pif, (uint8_t *)(void *)pdesc);

                    ep_ix = 0u;
                    pep = (USBH_EpDescTypeDef *)0;

                    /*
                     * Inner loop: parse endpoints.
                     * pif->bNumEndpoints is attacker-controlled (CVE-2021-42553).
                     * When bNumEndpoints > USBH_MAX_NUM_ENDPOINTS (2),
                     * writes past Ep_Desc[2] into adjacent memory.
                     */
                    while ((ep_ix < pif->bNumEndpoints) &&
                           (ptr < cfg_desc->wTotalLength))
                    {
                        pdesc = USBH_GetNextDesc((uint8_t *)(void *)pdesc,
                                                  &ptr);

                        if (pdesc->bDescriptorType == USB_DESC_TYPE_ENDPOINT)
                        {
                            pep = &cfg_desc->Itf_Desc[if_ix].Ep_Desc[ep_ix];
                            USBH_ParseEPDesc(pep,
                                             (uint8_t *)(void *)pdesc);
                            ep_ix++;
                        }
                    }
                }
                if_ix++;
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * USBH_Get_CfgDesc — reads config descriptor from USB device
 * (simplified from usbh_ctlreq.c)
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void USBH_Get_CfgDesc(USBH_HandleTypeDef *phost, uint16_t length)
{
    /* Clamp read length to buffer size */
    if (length > USBH_MAX_SIZE_CONFIGURATION) {
        length = USBH_MAX_SIZE_CONFIGURATION;
    }

    /*
     * In real HAL: issues GET_DESCRIPTOR control transfer on EP0.
     * USB device responds with raw descriptor bytes into CfgDesc_Raw.
     * Here: read from USB OTG FIFO register (attacker-controlled).
     */
    USB_ReadPacket(phost->device.CfgDesc_Raw, length);

    /* Parse the raw descriptor — vulnerable function */
    USBH_ParseCfgDesc(&phost->device.CfgDesc,
                       phost->device.CfgDesc_Raw,
                       length);
}

/* ═══════════════════════════════════════════════════════════════════════
 * USB enumeration — simulates the host enumeration sequence
 * ═══════════════════════════════════════════════════════════════════════ */
static USBH_HandleTypeDef g_usbh_host;

__attribute__((noinline))
static void USBH_Process_Enumeration(USBH_HandleTypeDef *phost)
{
    /*
     * USB enumeration step: Get full configuration descriptor.
     * First read 9 bytes to get wTotalLength, then read full descriptor.
     * In real code: two GET_DESCRIPTOR calls. Here: simplified to one.
     */

    /* Step 1: Read 9-byte config descriptor header to get wTotalLength */
    USB_ReadPacket(phost->device.CfgDesc_Raw, USB_CONFIGURATION_DESC_SIZE);
    uint16_t wTotalLength = LE16(phost->device.CfgDesc_Raw + 2);

    /* Step 2: Read full config descriptor (up to wTotalLength) */
    USBH_Get_CfgDesc(phost, wTotalLength);
}

/* ═══════════════════════════════════════════════════════════════════════ */

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    /* Clear host handle */
    memset(&g_usbh_host, 0, sizeof(g_usbh_host));

    /* Run USB enumeration — reads descriptors from malicious device */
    USBH_Process_Enumeration(&g_usbh_host);

    return 0;
}
