// Copyright 2018-2021 pwrdwnsys.
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use oui::OuiDatabase;

fn main() {

    env_logger::init();

    println!("Initialising new database from Wireshark file");
    let database1 = OuiDatabase::new_from_file("data/manuf.txt").unwrap();

    println!("Exporting Vendor database");
    let dump = database1.export().unwrap();

    println!("Importing Vendor database");
    let database2 = OuiDatabase::new_from_export(&dump).unwrap();

    assert_eq!(database1.len(), database2.len());

}