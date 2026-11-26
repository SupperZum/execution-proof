use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
};

#[test]
fn conditional_publish_requires_matching_generation_and_timely_readback() {
    for (upload_status, publication) in [
        ("200 OK", true),
        ("412 Precondition Failed", false),
        ("disconnect", false),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let name = key("grant", b"attempt");
            let expected = serde_json::to_vec(&Record {
                key: name.clone(),
                binding: hash(b"reserve"),
                payload: URL_SAFE_NO_PAD.encode(b"signed"),
            })
            .unwrap();
            let metadata = serde_json::json!({
                "bucket": "test-bucket", "name": name, "generation": "42",
                "timeFinalized": "1970-01-01T00:02:30.999Z",
            });
            let metadata = serde_json::to_vec(&metadata).unwrap();
            let object = format!("/storage/v1/b/test-bucket/o/{}", name.replace('/', "%2F"));
            let cases = [
                (format!("POST /upload/storage/v1/b/test-bucket/o?uploadType=media&name={}&ifGenerationMatch=0", name.replace('/', "%2F")), upload_status, &b""[..]),
                (format!("GET {object}?alt=json&projection=noAcl"), "200 OK", &metadata[..]),
                (format!("GET {object}?alt=media&ifGenerationMatch=42"), "200 OK", &expected[..]),
                (format!("GET {object}?alt=json&projection=noAcl"), "200 OK", &metadata[..]),
            ];
            for (request, status, reply) in cases {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), format!("{request} HTTP/1.1"));
                let mut authenticated = false;
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    let field = line.trim_end().to_ascii_lowercase();
                    if field.is_empty() {
                        break;
                    }
                    if field == "authorization: bearer fixture" {
                        authenticated = true;
                    }
                    if let Some(value) = field.strip_prefix("content-length: ") {
                        length = value.parse().unwrap();
                    }
                }
                assert!(authenticated);
                if request.starts_with("POST") {
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    assert_eq!(body, expected);
                    if status == "disconnect" {
                        // The object is committed, but the upload response never arrives.
                        continue;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .unwrap();
                stream.write_all(reply).unwrap();
            }
        });
        let journal = Journal {
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            bucket: "test-bucket".into(),
            endpoint: Url::parse(&endpoint).unwrap(),
            token: "fixture".into(),
        };
        let entry = journal
            .publish("grant", b"attempt", b"reserve", b"signed", Some((150, 151)))
            .unwrap();
        assert_eq!(entry.first, publication);
        assert_eq!(entry.payload, b"signed");
        assert_eq!(
            journal.read("grant", b"attempt", b"reserve", Some((149, 150))),
            Err(Error::Conflict)
        );
        worker.join().unwrap();
    }
}
