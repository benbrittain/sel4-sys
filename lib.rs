/* Copyright (c) 2015 The Robigalia Project Developers
 * Licensed under the Apache License, Version 2.0
 * <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT
 * license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
 * at your option. All files in the project carrying such
 * notice may not be copied, modified, or distributed except
 * according to those terms.
 */
#![no_std]
#![feature(asm, no_std, core_slice_ext)]
#![allow(bad_style, unused_parens, unused_assignments)]
#![doc(html_root_url = "https://doc.robigalia.org/")]

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!("arch/x86.rs");

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!("arch/arm.rs");

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/x86_invocation.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/arm_invocation.rs"));

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/x86_syscall_stub.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/arm_syscall_stub.rs"));

include!(concat!(env!("OUT_DIR"), "/types.rs"));
include!(concat!(env!("OUT_DIR"), "/syscalls.rs"));

pub type seL4_CNode = seL4_CPtr;
pub type seL4_IRQHandler = seL4_CPtr;
pub type seL4_IRQControl = seL4_CPtr;
pub type seL4_TCB = seL4_CPtr;
pub type seL4_Untyped = seL4_CPtr;
pub type seL4_DomainSet = seL4_CPtr;

pub const seL4_MsgLengthBits: usize = 7;
pub const seL4_MsgMaxLength: usize = 120;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxExtraCaps: usize = (1usize << seL4_MsgExtraCapBits) - 1;

pub struct seL4_IPCBuffer {
    pub tag: seL4_MessageInfo,
    pub msg: [seL4_Word; seL4_MsgMaxLength],
    pub userData: seL4_Word,
    pub caps_or_badges: [seL4_Word; seL4_MsgMaxExtraCaps],
    pub receiveCNode: seL4_CPtr,
    pub receiveIndex: seL4_CPtr,
    pub receiveDepth: seL4_CPtr,
}

pub enum seL4_CapRights {
    CanWrite = 0x01,
    CanRead = 0x02,
    CanGrant = 0x04,
    AllRights = 0x07,
}

pub static seL4_CapNull: seL4_Word          = 0; /* null cap */
pub static seL4_CapInitThreadTCB: seL4_Word = 1; /* initial thread's TCB cap */
pub static seL4_CapInitThreadCNode: seL4_Word     = 2; /* initial thread's root CNode cap */
pub static seL4_CapInitThreadVSpace: seL4_Word    = 3; /* initial thread's VSpace cap */
pub static seL4_CapIRQControl: seL4_Word    = 4; /* global IRQ controller cap */
pub static seL4_CapASIDControl: seL4_Word   = 5; /* global ASID controller cap */
pub static seL4_CapInitThreadASIDPool: seL4_Word  = 6; /* initial thread's ASID pool cap */
pub static seL4_CapIOPort: seL4_Word        = 7; /* global IO port cap (null cap if not supported) */
pub static seL4_CapIOSpace: seL4_Word       = 8; /* global IO space cap (null cap if no IOMMU support) */
pub static seL4_CapBootInfoFrame: seL4_Word = 9; /* bootinfo frame cap */
pub static seL4_CapInitThreadIPCBuffer: seL4_Word = 10; /* initial thread's IPC buffer frame cap */
pub static seL4_CapDomain: seL4_Word        = 11;  /* global domain controller cap */

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct seL4_SlotRegion {
    pub start: seL4_Word , /* first CNode slot position OF region */
    pub end: seL4_Word,   /* first CNode slot position AFTER region */
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct seL4_DeviceRegion {
    pub basePaddr: seL4_Word,     /* base physical address of device region */
    pub frameSizeBits: seL4_Word, /* size (2^n bytes) of a device-region frame */
    pub frames: seL4_SlotRegion,        /* device-region frame caps */
}

/* XXX: These MUST match the kernel config at build-time. */
pub const CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS: usize = 167;
pub const CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS: usize = 199;

#[repr(C)]
#[derive(Copy)]
pub struct seL4_BootInfo {
    pub nodeID: seL4_Word,          /* ID [0..numNodes-1] of the seL4 node (0 if uniprocessor) */
    pub numNodes: seL4_Word,        /* number of seL4 nodes (1 if uniprocessor) */
    pub numIOPTLevels: seL4_Word,   /* number of IOMMU PT levels (0 if no IOMMU support) */
    pub ipcBuffer: *mut seL4_IPCBuffer,       /* pointer to initial thread's IPC buffer */
    pub empty: seL4_SlotRegion,           /* empty slots (null caps) */
    pub sharedFrames: seL4_SlotRegion,    /* shared-frame caps (shared between seL4 nodes) */
    pub userImageFrames: seL4_SlotRegion, /* userland-image frame caps */
    pub userImagePDs: seL4_SlotRegion,    /* userland-image PD caps */
    pub userImagePTs: seL4_SlotRegion,    /* userland-image PT caps */
    pub untyped: seL4_SlotRegion,         /* untyped-object caps (untyped caps) */
    pub untypedPaddrList:   [seL4_Word; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS], /* physical address of each untyped cap */
    pub untypedSizeBitsList: [u8; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS], /* size (2^n) bytes of each untyped cap */
    pub initThreadCNodeSizeBits: u8, /* initial thread's root CNode size (2^n slots) */
    pub numDeviceRegions: seL4_Word,        /* number of device regions */
    pub deviceRegions: [seL4_DeviceRegion; CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS], /* device regions */
    pub initThreadDomain: u32, /* Initial thread's domain ID */
}

impl ::core::clone::Clone for seL4_BootInfo {
    fn clone(&self) -> Self {
        *self
    }
}
