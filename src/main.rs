use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::post,
};
use base64::Engine;
use futures_util::StreamExt;
use hickory_client::{
    client::{Client, ClientHandle},
    proto::{
        dnssec::{rdata::tsig::TsigAlgorithm, tsig::TSigner},
        op::{ResponseCode, UpdateMessage, update_message},
        rr::{
            DNSClass, Name, RData, Record, RecordSet, RecordType,
            rdata::{PTR, TXT},
        },
        runtime::TokioRuntimeProvider,
        udp::UdpClientStream,
        xfer::DnsHandle,
    },
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::{io::ErrorKind, net::IpAddr, sync::Arc};

type HmacSha256 = Hmac<Sha256>;
const RECORD_TTL: u32 = 60;

/// hmac-sha256 TSIG key
#[derive(Debug, Clone)]
struct UpdateKey {
    name: Arc<fqdn::Fqdn>,
    secret: Arc<[u8]>,
}

#[derive(Clone)]
struct DdnsConfig {
    /// This server's secret
    server_secret: Arc<[u8]>,

    /// DDNS zone
    ddns_zone: Arc<fqdn::Fqdn>,

    /// Connection to the authoritative server. UPDATE messages are TSIG-signed.
    dns: Client,
}

impl DdnsConfig {
    fn zone_name(&self) -> std::io::Result<Name> {
        Name::from_ascii(self.ddns_zone.to_string()).map_err(std::io::Error::other)
    }

    fn hostname_name(&self, hostname: &str) -> std::io::Result<Name> {
        Name::from_ascii(format!("{hostname}.{}", self.ddns_zone)).map_err(std::io::Error::other)
    }

    fn ptr_name_from_token(&self, token: &str) -> std::io::Result<Name> {
        let mut hash = HmacSha256::new_from_slice(&self.server_secret).expect("Oops");
        hash.update(token.as_ref());
        let hash = hash.finalize().into_bytes();
        Name::from_ascii(format!(
            "{}._token.{}",
            base32::encode(base32::Alphabet::Rfc4648HexLower { padding: false }, &hash,),
            self.ddns_zone,
        ))
        .map_err(std::io::Error::other)
    }

    async fn query(&self, name: Name, record_type: RecordType) -> std::io::Result<Vec<Record>> {
        let mut dns = self.dns.clone();
        let response = dns
            .query(name, DNSClass::IN, record_type)
            .await
            .map_err(std::io::Error::other)?;
        match response.response_code() {
            ResponseCode::NoError => Ok(response.answers().to_vec()),
            ResponseCode::NXDomain => Ok(Vec::new()),
            code => Err(std::io::Error::other(format!(
                "DNS query failed with {code}"
            ))),
        }
    }

    async fn send_update(
        &self,
        message: hickory_client::proto::op::Message,
    ) -> std::io::Result<()> {
        let response = self
            .dns
            .send(message)
            .next()
            .await
            .ok_or_else(|| std::io::Error::other("DNS server returned no response"))?
            .map_err(std::io::Error::other)?;
        match response.response_code() {
            ResponseCode::NoError => Ok(()),
            ResponseCode::YXDomain | ResponseCode::YXRRSet => Err(std::io::Error::new(
                ErrorKind::AlreadyExists,
                "DNS name or record already exists",
            )),
            ResponseCode::NXDomain | ResponseCode::NXRRSet => Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "DNS authorization prerequisite no longer exists",
            )),
            code => Err(std::io::Error::other(format!(
                "DNS update failed with {}",
                code
            ))),
        }
    }

    /// Atomically reserves the hostname and stores its hashed credential as a PTR.
    async fn create_hostname(&self, hostname: &str) -> std::io::Result<String> {
        let token: [u8; 16] = rand::random();
        let token = hex::encode(token);
        let hostname = self.hostname_name(hostname)?;
        let ptr_name = self.ptr_name_from_token(&token)?;
        let zone = self.zone_name()?;

        let marker = Record::from_rdata(
            hostname.clone(),
            RECORD_TTL,
            RData::TXT(TXT::new(vec!["ddns=1".to_owned()])),
        );
        let marker_set = RecordSet::from(marker.clone());
        let mut message = update_message::create(marker_set, zone, true);

        let mut ptr_absent = Record::update0(ptr_name.clone(), 0, RecordType::PTR);
        ptr_absent.set_dns_class(DNSClass::NONE);
        message.add_pre_requisite(ptr_absent.into_record_of_rdata());
        message.add_update(Record::from_rdata(
            ptr_name,
            RECORD_TTL,
            RData::PTR(PTR(hostname)),
        ));
        self.send_update(message).await?;
        Ok(token)
    }

    /// Resolves and strictly validates the credential record and hostname marker.
    async fn authorize(&self, token: &str) -> std::io::Result<(Name, Name)> {
        if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "invalid token",
            ));
        }

        let ptr_name = self.ptr_name_from_token(token)?;
        let answers = self.query(ptr_name.clone(), RecordType::PTR).await?;
        let [ptr_record] = answers.as_slice() else {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "invalid token",
            ));
        };
        let RData::PTR(ptr) = ptr_record.data() else {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "invalid token",
            ));
        };
        if ptr_record.name() != &ptr_name {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "invalid token",
            ));
        }
        let hostname = ptr.0.clone();

        let zone = self.zone_name()?;
        let hostname_label = hostname
            .iter()
            .next()
            .and_then(|label| std::str::from_utf8(label).ok());
        if hostname.base_name() != zone || !hostname_label.is_some_and(valid_hostname) {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "credential PTR target is outside the DDNS zone",
            ));
        }

        let marker_answers = self.query(hostname.clone(), RecordType::TXT).await?;
        let [marker] = marker_answers.as_slice() else {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "credential PTR target is not a managed hostname",
            ));
        };
        if marker.name() != &hostname
            || !matches!(marker.data(), RData::TXT(txt) if txt.txt_data().len() == 1 && txt.txt_data()[0].as_ref() == b"ddns=1")
        {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "credential PTR target is not a managed hostname",
            ));
        }
        Ok((ptr_name, hostname))
    }

    fn authorization_prerequisites(
        message: &mut hickory_client::proto::op::Message,
        ptr_name: Name,
        hostname: Name,
    ) {
        let mut ptr = Record::from_rdata(ptr_name, 0, RData::PTR(PTR(hostname.clone())));
        ptr.set_dns_class(DNSClass::IN);
        message.add_pre_requisite(ptr);
        let mut marker =
            Record::from_rdata(hostname, 0, RData::TXT(TXT::new(vec!["ddns=1".to_owned()])));
        marker.set_dns_class(DNSClass::IN);
        message.add_pre_requisite(marker);
    }

    async fn update_address(&self, token: &str, address: IpAddr) -> std::io::Result<Name> {
        let (ptr_name, hostname) = self.authorize(token).await?;
        let record_type = match address {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        };
        let mut message = update_message::delete_rrset(
            Record::update0(hostname.clone(), 0, record_type),
            self.zone_name()?,
            true,
        );
        Self::authorization_prerequisites(&mut message, ptr_name, hostname.clone());
        message.add_update(Record::from_rdata(
            hostname.clone(),
            RECORD_TTL,
            RData::from(address),
        ));
        self.send_update(message).await?;
        Ok(hostname)
    }

    async fn delete_hostname(&self, token: &str) -> std::io::Result<Name> {
        let (ptr_name, hostname) = self.authorize(token).await?;
        let mut message =
            update_message::delete_all(hostname.clone(), self.zone_name()?, DNSClass::IN, true);
        Self::authorization_prerequisites(&mut message, ptr_name.clone(), hostname.clone());
        let mut delete_ptr = Record::update0(ptr_name, 0, RecordType::ANY);
        delete_ptr.set_dns_class(DNSClass::ANY);
        message.add_update(delete_ptr.into_record_of_rdata());
        self.send_update(message).await?;
        Ok(hostname)
    }
}

fn json_response(status: StatusCode, response: serde_json::Value) -> axum::response::Response {
    (status, Json(response)).into_response()
}

async fn handler_create(
    State(state): State<DdnsConfig>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let hostname = params.get("hostname").cloned().unwrap_or_default();
    if !valid_hostname(&hostname) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "hostname must be a valid DNS label",
            }),
        );
    }

    let token = match state.create_hostname(&hostname).await {
        Ok(token) => token,
        Err(error) => return dns_error_response(error),
    };

    json_response(
        StatusCode::OK,
        json!({
            "error": Value::Null,
            "token": token,
        }),
    )
}

async fn handler_delete(
    State(state): State<DdnsConfig>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "token is required",
            }),
        );
    }

    match state.delete_hostname(&token).await {
        Ok(hostname) => json_response(
            StatusCode::OK,
            json!({
                "error": Value::Null,
                "hostname": hostname.to_ascii(),
            }),
        ),
        Err(error) => dns_error_response(error),
    }
}

async fn handler_update(
    State(state): State<DdnsConfig>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "token is required",
            }),
        );
    }

    let ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok());
    let Some(ip) = ip else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": "X-Real-IP must contain one IP address",
            }),
        );
    };

    match state.update_address(&token, ip).await {
        Ok(hostname) => json_response(
            StatusCode::OK,
            json!({
                "error": Value::Null,
                "hostname": hostname.to_ascii(),
                "address": ip.to_string(),
            }),
        ),
        Err(error) => dns_error_response(error),
    }
}

fn valid_hostname(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 63
        && !hostname.starts_with('-')
        && !hostname.ends_with('-')
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn dns_error_response(error: std::io::Error) -> axum::response::Response {
    let status = match error.kind() {
        ErrorKind::PermissionDenied => StatusCode::UNAUTHORIZED,
        ErrorKind::AlreadyExists => StatusCode::CONFLICT,
        _ => StatusCode::BAD_GATEWAY,
    };
    json_response(status, json!({ "error": error.to_string() })).into_response()
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let server_addr = std::env::var("SERVER_ADDR")
        .unwrap_or_default()
        .parse::<std::net::IpAddr>()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let listen_addr = std::env::var("LISTEN_ADDR")
        .unwrap_or_default()
        .parse::<std::net::SocketAddr>()
        .unwrap_or(std::net::SocketAddr::from(([127, 0, 0, 1], 3001)));
    let server_secret = std::env::var("SERVER_SECRET")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if server_secret.is_empty() {
        return Err(std::io::Error::other("SERVER_SECRET is not set"));
    }
    let server_secret: Vec<u8> = server_secret.into();
    let server_secret: Arc<[u8]> = server_secret.into();

    let ddns_zone = std::env::var("DDNS_ZONE")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if ddns_zone.is_empty() {
        return Err(std::io::Error::other("DDNS_ZONE is not set"));
    }
    let ddns_zone: fqdn::FQDN = ddns_zone.parse().map_err(std::io::Error::other)?;
    let ddns_zone: Box<fqdn::Fqdn> = unsafe { std::mem::transmute(ddns_zone) };
    let ddns_zone: Arc<fqdn::Fqdn> = ddns_zone.into();

    let update_key_path = std::env::var("UPDATE_KEY_PATH").unwrap_or("".to_string());

    let key_file = std::fs::read_to_string(update_key_path)?;
    let bytes = key_file.as_bytes();
    let mut tokens = Vec::with_capacity(12);
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b if b.is_ascii_whitespace() => pos += 1,
            b'#' => {
                pos += 1;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'/' if bytes.get(pos + 1) == Some(&b'/') => {
                pos += 2;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'/' if bytes.get(pos + 1) == Some(&b'*') => {
                let end = key_file[pos + 2..].find("*/").ok_or_else(|| {
                    std::io::Error::other("unterminated comment in TSIG key file")
                })?;
                pos += end + 4;
            }
            b'"' => {
                let start = pos + 1;
                pos = start;
                while pos < bytes.len() && bytes[pos] != b'"' {
                    if bytes[pos] == b'\\' {
                        return Err(std::io::Error::other(
                            "escaped strings are not valid in a TSIG key file",
                        ));
                    }
                    pos += 1;
                }
                if pos == bytes.len() {
                    return Err(std::io::Error::other(
                        "unterminated string in TSIG key file",
                    ));
                }
                tokens.push(&key_file[start..pos]);
                pos += 1;
            }
            b'{' | b'}' | b';' => {
                tokens.push(&key_file[pos..pos + 1]);
                pos += 1;
            }
            _ => {
                let start = pos;
                while pos < bytes.len()
                    && !bytes[pos].is_ascii_whitespace()
                    && !matches!(bytes[pos], b'{' | b'}' | b';' | b'"')
                {
                    pos += 1;
                }
                tokens.push(&key_file[start..pos]);
            }
        }
    }

    let invalid_key = || std::io::Error::other("invalid TSIG key file");
    if tokens.len() < 11
        || !tokens[0].eq_ignore_ascii_case("key")
        || tokens[2] != "{"
        || !tokens[3].eq_ignore_ascii_case("algorithm")
        || !tokens[4].eq_ignore_ascii_case("hmac-sha256")
        || tokens[5] != ";"
        || !tokens[6].eq_ignore_ascii_case("secret")
        || tokens[8] != ";"
        || tokens[9] != "}"
        || tokens[10] != ";"
        || tokens.len() != 11
    {
        return Err(invalid_key());
    }
    let name: fqdn::FQDN = tokens[1].parse().map_err(|_| invalid_key())?;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(tokens[7])
        .map_err(|error| std::io::Error::other(format!("invalid TSIG secret: {error}")))?;
    // `FQDN` and `Box<Fqdn>` are the owned and boxed forms of the same C-string
    // representation; the crate provides the inverse conversion using this layout.
    let name: Box<fqdn::Fqdn> = unsafe { std::mem::transmute(name) };
    let update_key: UpdateKey = UpdateKey {
        name: name.into(),
        secret: secret.into(),
    };

    let signer_name =
        Name::from_ascii(update_key.name.to_string()).map_err(std::io::Error::other)?;
    let signer = TSigner::new(
        update_key.secret.to_vec(),
        TsigAlgorithm::HmacSha256,
        signer_name,
        300,
    )
    .map_err(std::io::Error::other)?;
    let stream = UdpClientStream::builder(
        std::net::SocketAddr::new(server_addr, 53),
        TokioRuntimeProvider::new(),
    )
    .with_signer(Some(Arc::new(signer)))
    .build();
    let (dns, dns_background) = Client::connect(stream)
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(dns_background);

    let config = DdnsConfig {
        server_secret,
        ddns_zone,
        dns,
    };

    let app = Router::new()
        .route("/create", post(handler_create))
        .route("/delete", post(handler_delete))
        .route("/update", post(handler_update))
        .with_state(config);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
