use std::io;
use std::mem;
use std::time::{Duration, Instant};

// Linux socket 常數
const AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
struct sockaddr_ll {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const sockaddr_ll, addrlen: u32) -> i32;
    fn recvfrom(
        sockfd: i32,
        buf: *mut u8,
        len: usize,
        flags: i32,
        src_addr: *mut sockaddr_ll,
        addrlen: *mut u32,
    ) -> isize;
    fn close(fd: i32) -> i32;
    fn htons(hostshort: u16) -> u16;
}

struct RawSocket {
    fd: i32,
}

impl RawSocket {
    fn new() -> io::Result<Self> {
        unsafe {
            let fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL) as i32);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            
            // 綁定到所有介面 (ifindex = 0)
            let addr = sockaddr_ll {
                sll_family: AF_PACKET as u16,
                sll_protocol: htons(ETH_P_ALL),
                sll_ifindex: 0,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            
            if bind(fd, &addr, mem::size_of::<sockaddr_ll>() as u32) < 0 {
                close(fd);
                return Err(io::Error::last_os_error());
            }
            
            Ok(RawSocket { fd })
        }
    }
    
    fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut addr: sockaddr_ll = mem::zeroed();
            let mut addrlen = mem::size_of::<sockaddr_ll>() as u32;
            
            let bytes = recvfrom(
                self.fd,
                buffer.as_mut_ptr(),
                buffer.len(),
                0,
                &mut addr,
                &mut addrlen,
            );
            
            if bytes < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(bytes as usize)
            }
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

fn main() -> io::Result<()> {
    println!("=== Raw Socket 封包抓取工具 ===");
    println!("注意: 需要 root 權限執行 (sudo)");
    println!("開始抓取封包，持續 60 秒...");
    println!("{}", "=".repeat(40));
    
    let socket = RawSocket::new()?;
    let mut buffer = vec![0u8; 65536];
    
    let start_time = Instant::now();
    let duration = Duration::from_secs(60);
    let mut packet_count = 0;
    
    while start_time.elapsed() < duration {
        match socket.recv(&mut buffer) {
            Ok(len) => {
                packet_count += 1;
                print_packet_info(packet_count, &buffer[..len]);
            }
            Err(e) => {
                eprintln!("接收封包錯誤: {}", e);
                break;
            }
        }
    }
    
    println!("{}", "=".repeat(40));
    println!("抓取完成!");
    println!("總共抓取 {} 個封包", packet_count);
    println!("執行時間: {:.2} 秒", start_time.elapsed().as_secs_f32());
    
    Ok(())
}

fn print_packet_info(count: usize, data: &[u8]) {
    println!("封包 #{}:", count);
    println!("  長度: {} 位元組", data.len());
    
    // 顯示前 16 位元組的十六進制內容
    let data_len = data.len().min(16);
    print!("  資料 (前 {} 位元組): ", data_len);
    
    for byte in &data[..data_len] {
        print!("{:02X} ", byte);
    }
    println!();
    
    // 解析乙太網幀
    if data.len() >= 14 {
        // MAC 地址
        print!("  目標 MAC: ");
        for i in 0..6 {
            print!("{:02X}", data[i]);
            if i < 5 { print!(":"); }
        }
        println!();
        
        print!("  來源 MAC: ");
        for i in 6..12 {
            print!("{:02X}", data[i]);
            if i < 11 { print!(":"); }
        }
        println!();
        
        // 乙太網類型
        let eth_type = u16::from_be_bytes([data[12], data[13]]);
        match eth_type {
            0x0800 => {
                println!("  類型: IPv4");
                if data.len() >= 34 {
                    println!("  來源 IP: {}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                    println!("  目標 IP: {}.{}.{}.{}", data[30], data[31], data[32], data[33]);
                }
            }
            0x0806 => println!("  類型: ARP"),
            0x86DD => println!("  類型: IPv6"),
            _ => println!("  類型: 0x{:04X}", eth_type),
        }
    }
    
    println!();
}