use pcap::{Capture, Device};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 簡單封包抓取工具 ===");
    
    // 獲取預設網路介面
    let device = Device::lookup()?
        .ok_or("找不到可用的網路介面")?;
    
    println!("使用網路介面: {}", device.name);
    println!("開始抓取封包，持續 60 秒...");
    println!("{}", "=".repeat(40));

    // 開啟抓取裝置
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .timeout(1000)
        .open()?;

    let start_time = Instant::now();
    let duration = Duration::from_secs(60);
    let mut packet_count = 0;

    while Instant::now().duration_since(start_time) < duration {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                print_packet_info(packet_count, &packet);
            }
            Err(pcap::Error::TimeoutExpired) => {
                // 超時是正常的，繼續檢查時間
                continue;
            }
            Err(e) => {
                eprintln!("抓取封包錯誤: {}", e);
                break;
            }
        }
        
        // 讓出 CPU
        sleep(Duration::from_millis(1)).await;
    }

    println!("{}", "=".repeat(40));
    println!("抓取完成!");
    println!("總共抓取 {} 個封包", packet_count);
    println!("執行時間: {:.2} 秒", start_time.elapsed().as_secs_f32());

    Ok(())
}

fn print_packet_info(count: usize, packet: &pcap::Packet) {
    println!("封包 #{}:", count);
    println!("  長度: {} 位元組", packet.header.len);
    println!("  實際長度: {} 位元組", packet.header.caplen);
    println!("  時間戳: {}.{:06}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
    
    // 顯示前 16 位元組的十六進制內容
    let data_len = packet.data.len().min(16);
    print!("  資料 (前 {} 位元組): ", data_len);
    
    for byte in &packet.data[..data_len] {
        print!("{:02X} ", byte);
    }
    println!();
    
    // 嘗試解析乙太網幀類型
    if packet.data.len() >= 14 {
        let eth_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
        match eth_type {
            0x0800 => println!("  類型: IPv4"),
            0x0806 => println!("  類型: ARP"),
            0x86DD => println!("  類型: IPv6"),
            _ => println!("  類型: 0x{:04X}", eth_type),
        }
    }
    
    println!();
}