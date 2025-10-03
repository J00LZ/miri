use std::{
    cell::RefCell,
    collections::HashMap,
    process::Command,
    rc::Rc,
    sync::{atomic::{AtomicBool, AtomicU32}, Arc},
};

use miripbt_format::{
    communication::{Client, Communication, RequestBody, ResponseBody, Server},
    MiriPBTFormat,
};

pub struct Pbt {
    pub format: MiriPBTFormat,
    _s: Option<Server>,
    c: Client,
    current_id: Arc<AtomicU32>,
    pub stop_after_first: bool,
    pub has_failed: AtomicBool,
    func_values: Rc<RefCell<HashMap<String, miripbt_format::communication::Value>>>,
}

impl Pbt {
    pub fn new(format: &MiriPBTFormat, stop_after_first: bool) -> Self {
        println!("creating command");
        let (s, port) = miripbt_format::communication::Server::new();
        println!("Opened port {port}");
        Command::new("structure_provider").arg(port.to_string()).spawn().unwrap();
        let s = s.with_client();

        println!("created command!");
        let mut s = Self {
            format: format.clone(),
            c: s.client().try_clone(),
            _s: Some(s),
            current_id: Arc::new(AtomicU32::new(0)),
            stop_after_first,
            has_failed: AtomicBool::new(false),
            func_values: Rc::new(RefCell::new(HashMap::new())),
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

    pub fn set_prev(&self, name: impl ToString, value: miripbt_format::communication::Value) {
        self.func_values.borrow_mut().insert(name.to_string(), value);
    }

    /// returns true if they are the same, false if they are not
    pub fn are_equal(
        &self,
        name: &str,
        other: miripbt_format::communication::Value,
    ) -> Result<Vec<String>, String> {
        let current = self.func_values.borrow();
        if let Some(current) = current.get(name) {
            self.format.compare(name, current, &other)
        } else {
            Ok(vec![])
        }
    }
}

impl Clone for Pbt {
    fn clone(&self) -> Self {
        Self {
            format: self.format.clone(),
            _s: None,
            c: self.c.try_clone(),
            current_id: self.current_id.clone(),
            stop_after_first: self.stop_after_first,
            has_failed: AtomicBool::new(self.has_failed.load(std::sync::atomic::Ordering::SeqCst)),
            func_values: self.func_values.clone(),
        }
    }
}
