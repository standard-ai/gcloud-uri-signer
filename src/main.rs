use itertools::Itertools;
use rustls::{internal::pemfile, sign::SigningKey};
use std::error::Error as StdError;

#[derive(Clone, Debug, structopt::StructOpt)]
#[structopt(
    name = "gcloud-uri-signer",
    about = "A basic authentication proxy for google storage (and possibly other services)"
)]
struct Opts {
    /// Bind address
    #[structopt(short = "b", long = "bind", default_value = "[::1]:80")]
    bind: std::net::SocketAddr,

    /// Hex-digests of a SHA256-hashed `<username>:<password>` pairs
    ///
    /// Either `<username>` or `<password>` may be empty strings
    #[structopt(short = "c", long = "credentials", min_values=0, value_delimiter=",")]
    creds: Vec<String>,

    /// Allow signing PUT requests
    #[structopt(long = "put")]
    put: bool,

    /// Allow signing POST requests
    #[structopt(long = "post")]
    post: bool,

    /// Allow signing DELETE requests
    #[structopt(long = "delete")]
    delete: bool,

    /// Authority (aka. domain) for signed URIs
    ///
    /// Provided a request to /file.tar, `https://{authority}/file.tar` will be signed
    #[structopt(
        short = "a",
        long = "authority",
        default_value = "storage.googleapis.com"
    )]
    authority: http::uri::Authority,

    /// Scope argument used when signing the request
    #[structopt(long = "sign_scope", default_value = "auto/storage/goog4_request")]
    sign_scope: String,

    /// Path to the service account key file
    #[structopt(short = "k", long = "key", env = "GOOGLE_APPLICATION_CREDENTIALS")]
    key_path: std::path::PathBuf,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Cannot convert {1:?} to a string")]
    HeaderValueConversion(
        #[source] http::header::ToStrError,
        http::header::HeaderValue,
    ),
    #[error("URI {0:?} has no authority portion")]
    UriAuthority(http::Uri),
    #[error("Could not parse the private key as a valid PEM file")]
    PrivateKeyParse,
    #[error("Private key PEM file is empty")]
    PrivateKeyEmpty,
    #[error("Unable to initialize RSA private key")]
    RSAKeyCreate,
    #[error("Unable to select RSA signing scheme")]
    RSASchemeSelection,
    #[error("Unable to sign the url")]
    RSASign(#[source] rustls::TLSError),
    #[error("Unable to sign the url")]
    UriBuild(#[source] http::Error),
    #[error("Unable to sign the url")]
    PathAndQueryBuild(#[source] http::uri::InvalidUri),

    #[error("Unable to open service account file {1:?}")]
    OpenServiceAccountFile(#[source] std::io::Error, std::path::PathBuf),
    #[error("Unable to parse service account file {1:?}")]
    ParseServiceAccountFile(#[source] serde_json::Error, std::path::PathBuf),
    #[error("Cannot create async runtime")]
    CreateAsyncRuntime(#[source] tokio::io::Error),
    #[error("HTTP server failed")]
    HyperSpawnError(#[source] hyper::Error),
}

const FRAGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'@')
    .add(b'/');

#[derive(serde::Serialize, serde::Deserialize)]
struct ServiceAccountKey {
    #[serde(rename = "type")]
    pub key_type: String,
    pub private_key: String,
    pub client_email: String,
}

/// Sign the google API URL.
///
/// # Example
///
/// ```
/// sign_bucket_url(service_account, "auto/storage/goog4_request", 1, 2, 3);
/// ```
fn sign_bucket_url(
    service_account: &ServiceAccountKey,
    scope: &str,
    uri: &http::Uri,
    expiration: std::time::Duration,
    http_method: &http::Method,
    mut headers: http::HeaderMap,
) -> Result<http::Uri, Error> {
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y%m%dT%H%M%SZ");
    let datestamp = now.format("%Y%m%d");

    // headers
    let authority = uri
        .authority()
        .ok_or_else(|| Error::UriAuthority(uri.clone()))?;
    headers.insert(
        http::header::HOST,
        http::header::HeaderValue::from_str(authority.as_str())
            .expect("Authority is a valid HeaderValue"),
    );
    let mut sorted_headers = headers
        .into_iter()
        .filter_map(|(k, v)| k.map(|k| (k, v)))
        .collect::<Vec<_>>();
    sorted_headers.sort_unstable_by(|(k1, v1), (k2, v2)| {
        (k1.as_str(), v1.as_bytes()).cmp(&(k2.as_str(), v2.as_bytes()))
    });
    let signed_headers: String = sorted_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .intersperse(";")
        .collect();
    let canonical_headers = sorted_headers
        .into_iter()
        .map(|(k, v)| {
            Ok(format!(
                "{}:{}\n",
                k.as_str(),
                v.to_str()
                    .map_err(|e| Error::HeaderValueConversion(e, v.clone()))?
                    .to_lowercase()
            ))
        })
        .collect::<Result<String, _>>()?;

    let canonical_path = uri.path();
    // query stuff
    let goog_credential = format!("{}/{}/{}", service_account.client_email, datestamp, scope);
    let mut sorted_query = vec![
        ("x-goog-algorithm", String::from("GOOG4-RSA-SHA256")),
        ("x-goog-credential", String::from(&goog_credential)),
        ("x-goog-date", format!("{}", timestamp)),
        ("x-goog-expires", format!("{}", expiration.as_secs())),
        ("x-goog-signedHeaders", signed_headers.clone()),
    ];
    sorted_query.extend(uri.query().unwrap_or("").split("&").filter_map(|kv| {
        let mut kv = kv.split("=");
        Some((kv.next()?, String::from(kv.next()?)))
    }));
    sorted_query.sort();
    let canonical_query_string = sorted_query
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                percent_encoding::utf8_percent_encode(&v, FRAGMENT)
            )
        })
        .intersperse(String::from("&"))
        .collect::<String>();
    let canonical_request = [
        http_method.as_str(),
        canonical_path,
        &canonical_query_string,
        &canonical_headers,
        &signed_headers,
        "UNSIGNED-PAYLOAD",
    ]
    .join("\n");
    let hash = ring::digest::digest(&ring::digest::SHA256, canonical_request.as_bytes());
    let encoded = data_encoding::HEXLOWER.encode(hash.as_ref());
    let to_sign = format!(
        "GOOG4-RSA-SHA256\n{timestamp}\n{datestamp}/{scope}\n{hash}",
        timestamp = timestamp,
        datestamp = datestamp,
        scope = scope,
        hash = encoded
    );

    let pks = pemfile::pkcs8_private_keys(&mut service_account.private_key.as_bytes())
        .map_err(|_| Error::PrivateKeyParse)?;
    let pk = if let Some((pk, _)) = pks.split_first() {
        pk
    } else {
        return Err(Error::PrivateKeyEmpty)?;
    };
    let signed = rustls::sign::RSASigningKey::new(&pk)
        .map_err(|_| Error::RSAKeyCreate)?
        .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
        .ok_or(Error::RSASchemeSelection)?
        .sign(to_sign.as_bytes())
        .map_err(Error::RSASign)?;
    http::Uri::builder()
        .scheme("https")
        .authority(authority.clone())
        .path_and_query(
            http::uri::PathAndQuery::from_maybe_shared(format!(
                "{}?{}&x-goog-signature={}",
                canonical_path,
                canonical_query_string,
                data_encoding::HEXLOWER.encode(&signed)
            ))
            .map_err(Error::PathAndQueryBuild)?,
        )
        .build()
        .map_err(Error::UriBuild)
}

async fn service_fn(
    req: hyper::Request<hyper::Body>,
    opts: Opts,
    credset: std::collections::HashSet<String>,
) -> Result<hyper::Response<hyper::Body>, hyper::http::Error> {
    // Verify if we support this verb
    if (req.method() == http::Method::PUT && !opts.put)
        || (req.method() == http::Method::POST && !opts.post)
        || (req.method() == http::Method::DELETE && !opts.delete)
    {
        return hyper::Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(hyper::Body::empty());
    }

    // And check credentials.
    if !credset.is_empty() {
        let received_hash = req.headers().get(hyper::header::AUTHORIZATION).and_then(|ahdr| {
            base64::decode(&ahdr.as_bytes()[b"Basic ".len()..]).ok()
        }).map(|pair| {
            let hash = ring::digest::digest(&ring::digest::SHA256, &pair);
            data_encoding::HEXLOWER.encode(hash.as_ref())
        });
        if received_hash.map(|hash| credset.contains(&hash)) != Some(true) {
            return hyper::Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(hyper::Body::empty());
        }
    }

    // Prepend the expected authority before the path…
    let mut reqpath = req.uri().clone().into_parts();
    reqpath.scheme = Some(http::uri::Scheme::HTTPS);
    reqpath.authority = Some(opts.authority.clone());
    let data_path = http::Uri::from_parts(reqpath).unwrap();

    // And get it signed!
    let sign_scope = opts.sign_scope;
    let key_path = opts.key_path;
    let signed = (|| {
        let file = std::fs::File::open(&key_path)
            .map_err(|e| Error::OpenServiceAccountFile(e, key_path.clone()))?;
        let sa: ServiceAccountKey = serde_json::from_reader(file)
            .map_err(|e| Error::ParseServiceAccountFile(e, key_path.clone()))?;
        sign_bucket_url(
            &sa,
            &sign_scope,
            &data_path,
            std::time::Duration::new(15, 0),
            req.method(),
            http::HeaderMap::new(),
        )
    })();

    match signed {
        Ok(uri) => hyper::Response::builder()
            .status(http::StatusCode::TEMPORARY_REDIRECT)
            .header("location", uri.to_string())
            .body(hyper::Body::empty()),
        Err(_) => hyper::Response::builder()
            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(hyper::Body::empty()),
    }
}

fn run(opts: &Opts) -> Result<(), Error> {
    let mut threaded_rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .map_err(Error::CreateAsyncRuntime)?;
    let credset: std::collections::HashSet<String> = opts.creds.iter().cloned().collect();
    let server = threaded_rt.enter(move || {
        hyper::Server::bind(&opts.bind).serve(hyper::service::make_service_fn(move |_conn| {
            let (opts, credset) = (opts.clone(), credset.clone());
            async move {
                Ok::<_, std::convert::Infallible>(hyper::service::service_fn(move |req| {
                    service_fn(req, opts.clone(), credset.clone())
                }))
            }
        }))
    });
    threaded_rt.block_on(server).map_err(Error::HyperSpawnError)
}

fn main() {
    let opts = <Opts as structopt::StructOpt>::from_args();
    std::process::exit(match run(&opts) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            let mut source = e.source();
            while let Some(src) = source {
                eprintln!("  caused by: {}", src);
                source = src.source();
            }
            1
        }
    });
}
