/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "lwip/opt.h"

#if LWIP_NETCONN

#include "tcpecho.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "netif/ethernet.h"
#include "enet_ethernetif.h"

#include "board.h"

#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"

#include "aes.h"
#include "fsl_crc.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* IP address configuration. */
#define configIP_ADDR0 192
#define configIP_ADDR1 168
#define configIP_ADDR2 0
#define configIP_ADDR3 102

/* Netmask configuration. */
#define configNET_MASK0 255
#define configNET_MASK1 255
#define configNET_MASK2 255
#define configNET_MASK3 0

/* Gateway address configuration. */
#define configGW_ADDR0 192
#define configGW_ADDR1 168
#define configGW_ADDR2 0
#define configGW_ADDR3 100

/* MAC address configuration. */
#define configMAC_ADDR                     \
    {                                      \
        0x02, 0x12, 0x13, 0x10, 0x15, 0x11 \
    }

/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS

/* System clock name. */
#define EXAMPLE_CLOCK_NAME kCLOCK_CoreSysClk


#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void aescrc_test_task(void *arg);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Main function
 */
int main(void)
{
    static struct netif netif;
#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
    static mem_range_t non_dma_memory[] = NON_DMA_MEMORY_ARRAY;
#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
    ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
    ethernetif_config_t enet_config = {
        .phyAddress = EXAMPLE_PHY_ADDRESS,
        .clockName  = EXAMPLE_CLOCK_NAME,
        .macAddress = configMAC_ADDR,
#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
        .non_dma_memory = non_dma_memory,
#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
    };



    uint8_t test_string[]={0x48,0x4F,0x4C,0x41};
    /* AES data */
    //Llave secreta
    uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    //Vector de inicializacion
    uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    struct AES_ctx ctx;
    size_t test_string_len, padded_len;
    uint8_t padded_msg[512] = {0};
    /* CRC data */
    CRC_Type *base = CRC0;
    uint32_t checksum32;

    uint32_t seed;

    //SYSMPU_Type *base = SYSMPU;
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();


    crc_config_t config;

       config.polynomial         = 0x04C11DB7U;
       config.seed               = seed;
       config.reflectIn          = true;
       config.reflectOut         = true;
       config.complementChecksum = true;
       config.crcBits            = kCrcBits32;
       config.crcResult          = kCrcFinalChecksum;

       CRC_Init(base, &config);



    	PRINTF("Prueba de encriptacion AES 128 con padding\r\n");

    	for(int i=0;i<4;i++){
    	PRINTF("Mensaje: %X\r\n",test_string[i]);
    	}

    	PRINTF("\nTesting AES128\r\n\n");
    	/* Init the AES context structure */
    	AES_init_ctx_iv(&ctx, key, iv);

    	/* El arreglo debe ser de un numero de elementos multiplo de 16, sino se agregan ceros hasta completar*/
    	test_string_len = strlen(test_string);
    	padded_len = test_string_len + (16 - (test_string_len%16) );
    	memcpy(padded_msg, test_string, test_string_len);

    	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);

    	PRINTF("Encrypted Message: ");
    	for(int i=0; i<padded_len; i++) {
    		PRINTF("0x%02x,", padded_msg[i]);
    	}
    	PRINTF("\r\n");

/*
    	PRINTF("\nPrueba CRC32\r\n\n");

        //InitCrc32(base, 0xFFFFFFFFU);
        CRC_WriteData(base, (uint8_t *)&padded_msg[0], padded_len); // Se incluye CRC porque lo necesito para otra tarea.
        checksum32 = CRC_Get32bitResult(base);

        PRINTF("CRC-32: 0x%08x\r\n", checksum32);*/

    vTaskStartScheduler();

    /* Will not get here unless a task calls vTaskEndScheduler ()*/
    return 0;
}
#endif

/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */

