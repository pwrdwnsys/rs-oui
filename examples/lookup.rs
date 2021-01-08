// Copyright 2018-2021 pwrdwnsys.
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


use eui48::MacAddress;
use oui::OuiDatabase;

fn main() {
    env_logger::init();

    let db = OuiDatabase::new_from_file("data/manuf.txt").unwrap();

    println!("There are {} entries in the vendor database", db.len());

    let macaddr = MacAddress::parse_str("98:5a:eb:c6:f6:5d").unwrap();
    let res = db.query_by_mac(&macaddr).unwrap();
    println!("Query result is {:#?}", res);

    let res2 = db.query_by_str("00:00:18:00:20:01").unwrap();
    println!("Query result is {:#?}", res2);

}