use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Communication<T> {
    pub id: u32,
    pub data: T,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum RequestBody {
    Init(super::MiriPBTFormat),
    Request(super::TypeRefType),
    ReRequest(super::TypeRefType, Value, bool),
    End,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum ResponseBody {
    Ok,
    NoMoreFormats,
    Data(Value),
    Error(String),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum Value {
    Map(HashMap<String, Value>),
    String(String),
    Char(char),
    Bool(bool),
    UNum(u128),
    INum(i128),
    Float(f64),
    Unit,
}

pub struct Server {
    listener: TcpListener,
    c: Option<Client>,
}

impl Server {
    pub fn new() -> (Self, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        (Self { listener, c: None }, addr.port())
    }

    pub fn with_client(self) -> Self {
        if let Ok((stream, _)) = self.listener.accept() {
            println!("Client connected");
            Self { listener: self.listener, c: Some(Client { l: stream, buffer: String::new() }) }
        } else {
            panic!("Failed to accept client connection");
        }
    }

    pub fn client(&self) -> Client {
        self.c.as_ref().unwrap().try_clone()
    }
}

pub struct Client {
    l: TcpStream,
    buffer: String,
}

impl Client {
    pub fn connect(addr: u16) -> Self {
        let stream =
            TcpStream::connect(format!("127.0.0.1:{}", addr)).expect("Failed to connect to server");
        println!("Connected to server at port {}", addr);
        Self { l: stream, buffer: String::new() }
    }

    pub fn send<T: Serialize>(&mut self, data: &Communication<T>) -> std::io::Result<()> {
        let serialized = serde_json::to_string(data)?;
        self.l.write_all(serialized.as_bytes())?;
        self.l.write_all(b"\r\n")?;
        self.l.flush()?;
        Ok(())
    }

    pub fn receive<T: for<'de> Deserialize<'de>>(&mut self) -> std::io::Result<Communication<T>> {
        // read until \r\n is found, so don't use read_to_string, since that reads until EOF
        let mut temp_buffer = [0; 1024];
        let mut own_buffer = String::new();
        loop {
            let bytes_read = self.l.read(&mut temp_buffer)?;
            if bytes_read == 0 {
                break; // EOF
            }
            self.buffer.push_str(&String::from_utf8_lossy(&temp_buffer[..bytes_read]));
            if let Some((end, _)) = self.buffer.match_indices("\r\n").next() {
                own_buffer.push_str(&self.buffer[..end]);
                self.buffer.drain(..end + 2); // Remove the processed part including \r\n
                break;
            }
        }

        // Remove the trailing \r\n

        if let Some((end, _)) = own_buffer.match_indices("\r\n").next() {
            own_buffer.truncate(end);
        }
        let data: Communication<T> = serde_json::from_str(&own_buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(data)
    }

    pub fn try_clone(&self) -> Self {
        Self {
            l: self.l.try_clone().expect("Failed to clone TcpStream"),
            buffer: self.buffer.clone(),
        }
    }
}
