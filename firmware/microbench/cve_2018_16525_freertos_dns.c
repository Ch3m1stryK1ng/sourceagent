/*
 * CVE-2018-16525 Reproduction: FreeRTOS+TCP DNS/LLMNR Buffer Overflow
 *
 * Faithfully reproduces the vulnerable code path from FreeRTOS+TCP V2.0.6
 * (AWS FreeRTOS v1.3.1):
 *   - FreeRTOS_IP.c: prvProcessIPPacket() — trusts UDP header usLength
 *   - FreeRTOS_DNS.c: prvParseDNSReply() — no buffer length parameter
 *   - FreeRTOS_DNS.c: prvSkipNameField() — walks DNS names without bounds
 *
 * Original vulnerability: Attacker sends a crafted UDP DNS/LLMNR packet.
 * The UDP header's usLength field is trusted without validation and used
 * to set xDataLength. DNS parsing functions receive no buffer length and
 * walk memory without bounds checking. Response buffer allocation uses
 * the corrupted xDataLength, causing heap buffer overflow.
 *
 * Ground truth:
 *   - Source: ETH MAC RX FIFO @ 0x40029000 — raw Ethernet frame bytes
 *   - Sink 1: prvProcessIPPacket() — trusts UDP usLength from packet,
 *             overwrites xDataLength with attacker value (CVE-2018-16525)
 *   - Sink 2: prvSkipNameField() — walks DNS labels without bounds check,
 *             reads past buffer end (CWE-125 / CWE-787)
 *   - Sink 3: prvParseDNSReply() → memcpy for LLMNR response uses
 *             corrupted xDataLength as copy size (CWE-120)
 *
 * Struct definitions from FreeRTOS+TCP V2.0.6.
 * Function logic from FreeRTOS_DNS.c / FreeRTOS_IP.c v1.3.1.
 *
 * CWE-120: Buffer Copy without Checking Size of Input
 * CVSS: 8.1 (Network, no auth)
 * Fixed in: AWS FreeRTOS v1.3.2 / FreeRTOS+TCP V2.0.7
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
 * STM32 Ethernet MAC peripheral (source of attacker-controlled data)
 *
 * ETH_BASE = 0x40028000 (STM32F4/F7/H7)
 * ETH_DMASR = base + 0x1014  (DMA status register)
 * RX FIFO   = base + 0x1000  (DMA receive data via descriptor)
 * ═══════════════════════════════════════════════════════════════════════ */
#define ETH_BASE         0x40028000u
#define ETH_DMASR        (*(volatile uint32_t *)(ETH_BASE + 0x1014u))
#define ETH_RX_FIFO      (*(volatile uint32_t *)(ETH_BASE + 0x1000u))

/* DMA status bits */
#define ETH_DMASR_RS     (1u << 6)   /* Receive status: frame available */

/* ═══════════════════════════════════════════════════════════════════════
 * Network packet header structs
 * (verbatim from FreeRTOS+TCP V2.0.6 FreeRTOS_IP_Private.h)
 * ═══════════════════════════════════════════════════════════════════════ */
typedef struct {
    uint8_t  ucBytes[6];
} MACAddress_t;

typedef struct __attribute__((packed)) {
    MACAddress_t xDestinationAddress;   /* 6 bytes */
    MACAddress_t xSourceAddress;        /* 6 bytes */
    uint16_t     usFrameType;           /* 2 bytes — total: 14 */
} EthernetHeader_t;

typedef struct __attribute__((packed)) {
    uint8_t  ucVersionHeaderLength;     /* version (4b) + IHL (4b) */
    uint8_t  ucDifferentiatedServicesCode;
    uint16_t usLength;                  /* Total IP packet length */
    uint16_t usIdentification;
    uint16_t usFragmentOffset;
    uint8_t  ucTimeToLive;
    uint8_t  ucProtocol;                /* 0x11 = UDP */
    uint16_t usHeaderChecksum;
    uint32_t ulSourceIPAddress;
    uint32_t ulDestinationIPAddress;
} IPHeader_t;

typedef struct __attribute__((packed)) {
    uint16_t usSourcePort;
    uint16_t usDestinationPort;
    uint16_t usLength;                  /* CVE root cause: this field trusted */
    uint16_t usChecksum;
} UDPHeader_t;

/* Combined UDP packet (as FreeRTOS sees it in the network buffer) */
typedef struct __attribute__((packed)) {
    EthernetHeader_t xEthernetHeader;   /* 14 bytes */
    IPHeader_t       xIPHeader;         /* 20 bytes */
    UDPHeader_t      xUDPHeader;        /* 8 bytes — total: 42 */
} UDPPacket_t;

/* ═══════════════════════════════════════════════════════════════════════
 * DNS message structures
 * (verbatim from FreeRTOS_DNS.c V2.0.6)
 * ═══════════════════════════════════════════════════════════════════════ */
typedef struct __attribute__((packed)) {
    uint16_t usIdentifier;
    uint16_t usFlags;
    uint16_t usQuestions;
    uint16_t usAnswers;
    uint16_t usAuthorityRRs;
    uint16_t usAdditionalRRs;
} DNSMessage_t;

/* DNS answer record (used in LLMNR response construction) */
typedef struct __attribute__((packed)) {
    uint8_t  ucNameCode;
    uint8_t  ucNameOffset;
    uint16_t usType;
    uint16_t usClass;
    uint32_t ulTTL;
    uint16_t usDataLength;
    uint32_t ulIPAddress;
} LLMNRAnswer_t;

/* DNS name compression flag */
#define dnsNAME_IS_OFFSET  0xC0u

/* Protocol numbers */
#define ipPROTOCOL_UDP     0x11u

/* DNS/LLMNR ports */
#define dnsDNS_PORT        53u
#define dnsLLMNR_PORT      5355u

/* DNS record types */
#define dnsTYPE_A_HOST     1u
#define dnsCLASS_IN        1u

/* ═══════════════════════════════════════════════════════════════════════
 * NetworkBufferDescriptor_t — simplified from FreeRTOS+TCP
 * ═══════════════════════════════════════════════════════════════════════ */
#define ipBUFFER_PADDING    2u
#define NETWORK_BUFFER_SIZE 1536u  /* Typical MTU + headers */

typedef struct {
    uint8_t  *pucEthernetBuffer;
    uint32_t  xDataLength;        /* CVE root cause: overwritten with UDP usLength */
    uint16_t  usPort;
    uint32_t  ulIPAddress;
} NetworkBufferDescriptor_t;

/* Static network buffer */
static uint8_t g_rx_buffer[NETWORK_BUFFER_SIZE];
static NetworkBufferDescriptor_t g_net_buf;

/* Byte-swap for network order (big-endian) */
static inline uint16_t FreeRTOS_ntohs(uint16_t val) {
    return (uint16_t)((val >> 8) | (val << 8));
}

/* ═══════════════════════════════════════════════════════════════════════
 * ETH_ReadFrame — reads raw Ethernet frame from MAC RX FIFO
 *
 * In real STM32 HAL: HAL_ETH_GetReceivedFrame() via DMA descriptors.
 * Here: reads 32-bit words from the ETH RX FIFO register.
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static uint32_t ETH_ReadFrame(uint8_t *dest, uint32_t max_len)
{
    /* Wait for frame available */
    while (!(ETH_DMASR & ETH_DMASR_RS)) {}
    ETH_DMASR = ETH_DMASR_RS;  /* Clear status */

    /* Read frame length from first FIFO word (simplified) */
    uint32_t frame_len = ETH_RX_FIFO & 0xFFFFu;  /* MMIO_READ */
    if (frame_len > max_len) {
        frame_len = max_len;
    }

    /* Read frame data */
    uint32_t count32 = (frame_len + 3u) / 4u;
    uint32_t *dst32 = (uint32_t *)(void *)dest;
    for (uint32_t i = 0; i < count32; i++) {
        dst32[i] = ETH_RX_FIFO;  /* MMIO_READ: attacker-controlled */
    }

    return frame_len;
}

/* ═══════════════════════════════════════════════════════════════════════
 * prvSkipNameField — walks DNS name labels WITHOUT bounds checking
 * (verbatim from FreeRTOS_DNS.c V2.0.6, line ~680)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 2 (CVE-2018-16525): No buffer length parameter          ║
 * ║                                                                ║
 * ║  Walks DNS label chain: each label starts with length byte,   ║
 * ║  then that many characters. Attacker controls label lengths.  ║
 * ║  Loop runs until NULL byte — can walk past buffer end.        ║
 * ║  Compressed names (0xC0 prefix) skip 2 bytes, also unchecked. ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static uint8_t *prvSkipNameField(uint8_t *pucByte)
{
    if ((*pucByte & dnsNAME_IS_OFFSET) == dnsNAME_IS_OFFSET)
    {
        /* Compressed name: 2-byte offset pointer */
        pucByte += sizeof(uint16_t);  /* No check if 2 bytes available */
    }
    else
    {
        /* Walk label-by-label until NULL terminator */
        while (*pucByte != 0x00u)     /* No bounds check */
        {
            pucByte += (*pucByte + 1u); /* Attacker controls label length */
        }
        pucByte++;  /* Skip the NULL */
    }

    return pucByte;
}

/* ═══════════════════════════════════════════════════════════════════════
 * prvParseDNSReply — THE MAIN VULNERABLE DNS PARSER
 * (verbatim logic from FreeRTOS_DNS.c V2.0.6, line 741)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 3 (CVE-2018-16525): No buffer length parameter          ║
 * ║                                                                ║
 * ║  Function signature has NO length — cannot bounds-check.      ║
 * ║  Parses DNS question and answer records by walking memory.    ║
 * ║  usQuestions, usAnswers from attacker-controlled DNS header.   ║
 * ║  Each iteration calls prvSkipNameField (also unbounded).      ║
 * ║  Answer records: reads type/class/TTL/data without checking   ║
 * ║  remaining buffer space.                                      ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static uint32_t prvParseDNSReply(uint8_t *pucUDPPayloadBuffer,
                                  uint16_t xIdentifier)
{
    DNSMessage_t *pxDNSMessageHeader;
    uint32_t ulIPAddress = 0u;
    uint8_t *pucByte;
    uint16_t x, usQuestions, usAnswers;
    uint16_t usType, usDataLength;

    /* NO buffer length parameter — cannot validate bounds */

    pxDNSMessageHeader = (DNSMessage_t *)pucUDPPayloadBuffer;

    if (pxDNSMessageHeader->usIdentifier == xIdentifier)
    {
        pucByte = pucUDPPayloadBuffer + sizeof(DNSMessage_t);

        /* usQuestions from attacker-controlled DNS header */
        usQuestions = FreeRTOS_ntohs(pxDNSMessageHeader->usQuestions);

        /* Walk question records — each has name + type(2) + class(2) */
        for (x = 0; x < usQuestions; x++)
        {
            pucByte = prvSkipNameField(pucByte);  /* unbounded walk */
            /* No NULL check on return value */
            pucByte += sizeof(uint32_t);  /* skip type + class (4 bytes) */
            /* No check if 4 bytes available */
        }

        /* usAnswers from attacker-controlled DNS header */
        usAnswers = FreeRTOS_ntohs(pxDNSMessageHeader->usAnswers);

        /* Walk answer records */
        for (x = 0; x < usAnswers; x++)
        {
            pucByte = prvSkipNameField(pucByte);  /* unbounded walk */

            /* Read answer record fields — NO bounds check */
            usType = (uint16_t)((pucByte[0] << 8) | pucByte[1]);
            pucByte += 2;  /* type */
            pucByte += 2;  /* class */
            pucByte += 4;  /* TTL */

            usDataLength = (uint16_t)((pucByte[0] << 8) | pucByte[1]);
            pucByte += 2;  /* data length */

            if (usType == dnsTYPE_A_HOST && usDataLength == 4u)
            {
                /* Extract IPv4 address from answer */
                memcpy(&ulIPAddress, pucByte, sizeof(uint32_t));
            }

            pucByte += usDataLength;  /* skip data — attacker controls length */
        }
    }

    return ulIPAddress;
}

/* ═══════════════════════════════════════════════════════════════════════
 * prvProcessIPPacket — extracts UDP payload length
 * (simplified from FreeRTOS_IP.c V2.0.6, line 1570)
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SINK 1 (CVE-2018-16525): UDP usLength trusted from packet    ║
 * ║                                                                ║
 * ║  xDataLength is overwritten with value from UDP header.       ║
 * ║  Attacker sends usLength = 0xFFFF in UDP header.              ║
 * ║  xDataLength (originally = actual frame size) becomes 65527.  ║
 * ║  Downstream code allocates/copies using this corrupted value. ║
 * ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void prvProcessIPPacket(NetworkBufferDescriptor_t *pxNetworkBuffer)
{
    UDPPacket_t *pxUDPPacket;
    uint8_t *pucUDPPayloadBuffer;

    pxUDPPacket = (UDPPacket_t *)pxNetworkBuffer->pucEthernetBuffer;

    if (pxUDPPacket->xIPHeader.ucProtocol == ipPROTOCOL_UDP)
    {
        /*
         * BUG (CVE-2018-16525): Blindly trusts the UDP header's usLength.
         *
         * In v1.3.1 this line overwrites xDataLength with attacker value:
         *   pxNetworkBuffer->xDataLength =
         *       FreeRTOS_ntohs(pxUDPPacket->xUDPHeader.usLength) - sizeof(UDPHeader_t);
         *
         * No validation against actual frame size.
         */
        pxNetworkBuffer->xDataLength =
            FreeRTOS_ntohs(pxUDPPacket->xUDPHeader.usLength)
            - sizeof(UDPHeader_t);

        pxNetworkBuffer->usPort = pxUDPPacket->xUDPHeader.usSourcePort;
        pxNetworkBuffer->ulIPAddress = pxUDPPacket->xIPHeader.ulSourceIPAddress;

        /* Check if this is a DNS/LLMNR packet */
        uint16_t usDstPort = FreeRTOS_ntohs(pxUDPPacket->xUDPHeader.usDestinationPort);
        if (usDstPort == dnsDNS_PORT || usDstPort == dnsLLMNR_PORT)
        {
            /* Get pointer to UDP payload (DNS message starts here) */
            pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer
                                  + sizeof(UDPPacket_t);

            DNSMessage_t *pxDNSHeader = (DNSMessage_t *)pucUDPPayloadBuffer;

            /* Call vulnerable DNS parser — NO buffer length passed */
            prvParseDNSReply(pucUDPPayloadBuffer,
                             pxDNSHeader->usIdentifier);

            /*
             * For LLMNR response: allocate response buffer using
             * corrupted xDataLength — causes heap buffer overflow.
             * (Simplified: just demonstrate the memcpy with bad length)
             */
            if (usDstPort == dnsLLMNR_PORT)
            {
                uint8_t response[128];
                uint32_t copy_len = pxNetworkBuffer->xDataLength;

                /* SINK: memcpy with attacker-controlled length into
                 * fixed response buffer. xDataLength was set from UDP
                 * header, can be up to 65527. response is 128 bytes. */
                if (copy_len > 0) {
                    memcpy(response, pucUDPPayloadBuffer, copy_len);
                }
                (void)response;
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Network receive loop — simulates FreeRTOS IP task
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((noinline))
static void prvIPTask(void)
{
    while (1) {
        /* Read a frame from the Ethernet MAC */
        uint32_t frame_len = ETH_ReadFrame(g_rx_buffer, NETWORK_BUFFER_SIZE);

        if (frame_len >= sizeof(UDPPacket_t)) {
            /* Set up network buffer descriptor */
            g_net_buf.pucEthernetBuffer = g_rx_buffer;
            g_net_buf.xDataLength = frame_len;

            /* Process the IP packet */
            prvProcessIPPacket(&g_net_buf);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════ */

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    memset(g_rx_buffer, 0, sizeof(g_rx_buffer));
    memset(&g_net_buf, 0, sizeof(g_net_buf));

    /* Run the IP task (receive and process packets) */
    prvIPTask();

    return 0;
}
