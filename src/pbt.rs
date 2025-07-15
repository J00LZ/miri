use std::{
    process::Command,
    sync::{atomic::AtomicU32, Arc},
};

use miripbt_format::{
    communication::{Client, Communication, RequestBody, ResponseBody, Server},
    MiriPBTFormat,
};

pub struct Pbt {
    pub format: MiriPBTFormat,
    s: Option<Server>,
    c: Client,
    current_id: Arc<AtomicU32>,
}

impl Pbt {
    pub fn new(format: &MiriPBTFormat) -> Self {
        println!("creating command");
        let (s, port) = miripbt_format::communication::Server::new();
        println!("Opened port {port}");
        Command::new("structure_provider").arg(&port.to_string()).spawn().unwrap();
        let s = s.with_client();

        println!("created command!");
        let mut s = Self {
            format: format.clone(),
            c: s.client().try_clone(),
            s: Some(s),
            current_id: Arc::new(AtomicU32::new(0)),
        };
        println!("Sending format!");
        // Send the format to the structure provider.
        // we don't care about the reply, since there is none
        let _res = s.write(RequestBody::Init(format.clone()));
        s
    }

    pub fn write(&mut self, data: RequestBody) -> ResponseBody {
        let id = self.current_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let msg = Communication { id, data };

        self.c.send(&msg).expect("Failed to send data to structure provider");
        self.c.receive().ok().map(|it| it.data).unwrap()
    }
}

impl Clone for Pbt {
    fn clone(&self) -> Self {
        Self {
            format: self.format.clone(),
            s: None,
            c: self.c.try_clone(),
            current_id: self.current_id.clone(),
        }
    }
}
