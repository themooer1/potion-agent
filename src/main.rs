use core::slice;
use std::{error::Error, fs::File, io::Read, mem, os::fd::IntoRawFd, ptr};

// use libc::c_ulong;
use nix::{fcntl::{open, OFlag}, ioctl_write_int_bad, mount::*, request_code_none, sys::stat::Mode};

const NAME_MAX: usize = 255;

type autofs_wqt_t = u32;

#[repr(C)]
#[derive(Debug)]
struct autofs_packet_hdr {
        proto_version: i32,              /* Protocol version */
        packet_type: i32                       /* Type of packet */
}

#[repr(C)]
#[derive(Debug)]
struct autofs_v5_packet {
        hdr: autofs_packet_hdr,
        wait_queue_token: autofs_wqt_t,
        dev: u32,
        ino: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        tgid: u32,
        len: u32,
        name: [u8; NAME_MAX + 1],
}

const AUTOFS_IOC_MAGIC: u8 = 0x93;
const AUTOFS_IOC_TYPE_READY: u8 = 0x60;
// const CTL: u32 = (((0) << (((0+8)+8)+14)) | (((0x93)) << (0+8)) | (((0x60)) << 0) | ((0) << ((0+8)+8))); 
ioctl_write_int_bad!(autofs_ready, request_code_none!(AUTOFS_IOC_MAGIC, AUTOFS_IOC_TYPE_READY));
// ioctl_write_int_bad!(autofs_ready, CTL);
// ioctl_none!(autofs_ready, AUTOFS_IOC_MAGIC, AUTOFS_IOC_TYPE_READY);
// ioctl_none!(autofs_ready, AUTOFS_IOC_MAGIC, AUTOFS_IOC_TYPE_READY);

fn mount_backing() -> Result<(), Box<dyn Error>> {
    mount::<str, str, str, str>(None, "/mnt/mcauto", Some("tmpfs"), MsFlags::empty(), Some("rw,mode=1777"))?;

    Ok(())
}

fn start_autofs() -> Result<(), Box<dyn Error>> {
    println!("Creating autofs pipe");
    let (rdfd, wrfd) = nix::unistd::pipe()?;
    let wrfd = wrfd.into_raw_fd();

    println!("Creating autofs mount");
    let mount_options = format!("fd={},minproto=5", wrfd);
    mount::<str, str, str, str>(None, "/mnt/mcauto", Some("autofs"), MsFlags::empty(), Some(&mount_options))?;

    println!("Setup autofs");

    println!("mounting autofs root");
    let mnt_fd = open("/mnt/mcauto", OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())?;
    println!("mounted autofs root");

    let mut autofs_notifications = File::from(rdfd);

    let mut packet: autofs_v5_packet;

    unsafe {packet = mem::zeroed();}

    {
        let slice = unsafe{slice::from_raw_parts_mut(ptr::from_mut(&mut packet) as *mut u8, std::mem::size_of::<autofs_v5_packet>())};
        autofs_notifications.read_exact(slice)?;

    }

    println!("notification: {:?}", packet);
    
    println!("mounting tmpfs");
    mount_backing()?;
    println!("mounted tmpfs");


    println!("signaling ready");
    unsafe {
        autofs_ready(mnt_fd, packet.wait_queue_token as i32)?;
    }
    println!("signaled ready");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>>{
    println!("Hello, world!");

    match start_autofs() {
        Ok(()) => {},
        Err(e) => {println!("AutoFS Error: {}", e)},
    }

    Ok(())
}
