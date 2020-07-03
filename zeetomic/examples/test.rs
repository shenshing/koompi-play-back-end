#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
extern crate rocket_cors;

extern crate curl;

use curl::easy::Easy;
use std::io::{stdout, Write, stdin, Read};
use std::str;

#[macro_use]
extern crate json;
// use models::stringObj;
use zeetomic::models::*;
use zeetomic::wallet::*;


fn main() {


    // let cors = rocket_cors::CorsOptions::default().to_cors().unwrap();

    // rocket::ignite()
    //     .mount("/", routes![save_wallet_to_db])
    //     .mount("/", routes![get_wallet_info])
    //     .attach(cors)
    //     .launch();

    let mut result: String = String::from("");
    let mut data = Vec::new();
    let mut handle = Easy::new();
    handle.url("https://backend.satisyou.com").unwrap();
    {
        let mut transfer = handle.transfer();
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }
    result = String::from_utf8(data).unwrap();

    println!("{}", result);

    // let mut string = String::from("hello");
    // let mut data_to_upload = &b"foobar"[..];


    // let mut data_to_upload = json::parse(r#"
    //     {
    //         "string" : "hello"
    //     }
    // "#).unwrap();

    // println!("{:#?}", data_to_upload);

    // let mut data_to_upload = object!{
    //     "string" : "hello"
    // };

    // let data = &data_to_upload["string"];
    // let mut data_to_upload = "this is body".as_bytes();

    // let mut data_to_uplad = "
    //     {
    //         \"string\": \"hello\"
    //     }
    // ".as_bytes();


    // println!("{}", data);
    // let st = format!("{}", data);

    // println!("{:#?}", data_to_upload);
    // println!("{}", data_to_upload["string"]);


/*
    let mut data = st {
        string:  String::from("hello")
    };

    let mut data_serialize = serde_json::to_string(&data).unwrap();
    let mut data_to_upload = data_serialize.as_bytes();
    // println!("{}", data_to_upload);
    let html = String::new();

    let mut return_data = Vec::new();
    let mut handle = Easy::new();
    handle.url("http://localhost:8000/request").unwrap();

    handle.post(true).unwrap();

    {
        let mut transfer = handle.transfer();
        transfer.read_function(|into| {
        // return_data.extend_from_slice(into);
        html = String::from_utf8(Vec::from(into)).unwrap();
        Ok(data_to_upload.read(into).unwrap_or(0))
        }).unwrap();
        // transfer.write_function(|into| {
        //     return_data.extend_from_slice(into);
        //     // Ok(new_data.len())
        //     // let value = into;
        //     // Ok(data_to_upload.read(into).unwrap())
        //     let mut value = into.to_vec();
        //     Ok(data_to_upload.read(&mut value).unwrap())
        //     // Ok(data_to_upload.read(&mut into[..]).unwrap())
        // }).unwrap();
        transfer.perform().unwrap();
    }

*/
    // println!("{:#?}", return_data[3]);
    // let result = String::from_utf8(return_data).unwrap();
    // println!("{}", result);



    // let mut transfer = handle.transfer();
    // transfer.read_function(|into| {
    //     // Ok(data_to_upload["string"].read(into).unwrap())
    //     // Ok(st.as_bytes().read(into).unwrap())
    //     // return_data.extend_from_slice(into);
    //     // println!("{:#?}", into);
    //     return_data.push(into);
    //     Ok(data_to_upload.read(into).unwrap())

    // }).unwrap();
    // transfer.perform().unwrap();
    // println!("{:#?}", transfer);
    // let mut return_string = String::from_utf8(into).unwrap();



    // {
    //     let transfer = handle.transfer();

    // }

    // println!("{:#?}", handle);

    // let mut string = String::from("hello");
    // println!("{:#?}", string.as_bytes());

    // println!("{:#?}", handle);



    // let email = String::from("shing11@gmail.com");
    // let result = filter_wallet(email);
    // println!("{:#?}", result);
}