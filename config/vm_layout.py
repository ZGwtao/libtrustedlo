PAGE_SIZE = 0x1000

VM_REGIONS = [
    {
        "name": "IPC_BUFFER",
        "base": 0x00100000,
        "size": PAGE_SIZE,
    },
    {
        "name": "LOADER_PROGRAM",
        "base": 0x00200000,
        "size": 0x00800000,
    },
    {
        "name": "LOADER_METADATA",
        "base": 0x00A00000,
        "size": PAGE_SIZE,
    },
    {
        "name": "OSSVC_METADATA",
        "base": 0x00A01000,
        "size": PAGE_SIZE,
    },
    {
        "name": "TRAMPOLINE_ARGS",
        "base": 0x00A02000,
        "size": PAGE_SIZE,
    },
    {
        "name": "TRAMPOLINE_PROGRAM",
        "base": 0x01800000,
        "size": 0x00800000,
    },
    {
        "name": "CONTAINER_PROGRAM",
        "base": 0x02800000,
        "size": 0x00800000,
    },
    {
        "name": "LOADER_CONTEXT",
        "base": 0x00E00000,
        "size": PAGE_SIZE,
    },
    {
        "name": "CONTAINER_STACK",
        "base": 0x0000000FFFBFF000,
        "size": PAGE_SIZE,
    },
    {
        "name": "TRAMPOLINE_STACK",
        "base": 0x0000000FFFE00000,
        "size": PAGE_SIZE,
    },
    {
        "name": "TRAMPOLINE_IMAGE",
        "base": 0x01000000,
        "size": 0x00800000,
    },
    {
        "name": "CONTAINER_IMAGE",
        "base": 0x02000000,
        "size": 0x00800000,
    },
]