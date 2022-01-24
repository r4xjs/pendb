mod parser;
use crate::parser::nmap::NmapRun;

use serde_xml_rs::from_str;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;




fn main() -> Result<()> {
    

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
    	println!("Usage: {} <nmap-xml-file>", &args[0]);
    	return Ok(());
    }
    let nmap_xml = std::fs::read_to_string(&args[1])?;
    

    let nmap: NmapRun = from_str(&nmap_xml)?;

    dbg!(nmap);
    //for host in &nmap.hosts {
    //	for port in &host.ports.ports {
    //	    dbg!(port);
    //	}
    //}

    Ok(())
}
