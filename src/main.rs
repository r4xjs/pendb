mod parser;
mod db;
use crate::parser::nmap::NmapRun;
use crate::db::sqlite;

use serde_xml_rs::from_str;
use walkdir::WalkDir;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;




fn main() -> Result<()> {
    

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
    	println!("Usage: {} <log-dir>", &args[0]);
    	return Ok(());
    }

    for entry in WalkDir::new(&args[1])
    {
	let entry = entry?;
	if entry.file_name().to_str().unwrap().ends_with(".xml") {
	    let path = entry.into_path();
	    let nmap_xml = std::fs::read_to_string(&path)?;
	    let nmap = from_str::<NmapRun>(&nmap_xml)?;
	    println!("{}", &nmap.args);
	    //if let Ok(nmap) = from_str::<NmapRun>(&nmap_xml) {
	    //	println!("{}", &nmap.args);
	    //	//dbg!(&nmap);
	    //} else {
	    //	println!("fail");
	    //}

	}
    }

    Ok(())
}
