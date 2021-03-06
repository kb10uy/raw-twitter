use async_std::{fs::File, io::BufReader, prelude::*};
use std::{
    collections::BTreeMap,
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::encode as base64_encode;
use clap::Clap;
use dotenv::dotenv;
use envy::from_env;
use hmac::{Hmac, Mac, NewMac};
use log::{error, warn, debug};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rand::{seq::SliceRandom, thread_rng};
use serde::Deserialize;
use serde_json::{from_str, Value};
use sha1::Sha1;

const NONCE_CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
const RFC3986_ESCAPES: &AsciiSet = &CONTROLS
    // query set
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    // path set
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    // userinfo
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|')
    // component
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',');

type HmacSha1 = Hmac<Sha1>;
type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

/// Send a raw request to Twitter.
#[derive(Debug, Clap)]
struct Arguments {
    /// Request template file (*.json)
    template_file: String,

    /// Overrides some parameters in template file.
    #[clap(short, long = "param")]
    parameters: Vec<String>,
}

/// 環境変数
#[derive(Debug, Deserialize)]
struct Environments {
    #[serde(rename = "twitter_ck")]
    consumer_key: String,

    #[serde(rename = "twitter_cs")]
    consumer_secret: String,

    #[serde(rename = "twitter_at")]
    access_token: String,

    #[serde(rename = "twitter_ats")]
    access_token_secret: String,
}

/// HTTP メソッド
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Method {
    /// GET リクエスト
    Get,

    /// POST リクエスト
    Post,

    /// PUT リクエスト
    Put,

    /// DELETE リクエスト
    Delete,
}

impl ToString for Method {
    fn to_string(&self) -> String {
        match self {
            Method::Get => "GET".into(),
            Method::Post => "POST".into(),
            Method::Put => "PUT".into(),
            Method::Delete => "DELETE".into(),
        }
    }
}

/// リクエストテンプレートファイル
#[derive(Debug, Clone, Deserialize)]
struct Template {
    /// エンドポイント名
    endpoint: Box<str>,

    /// HTTP メソッド
    method: Method,

    /// クエリパラメーター
    parameters: BTreeMap<Box<str>, Value>,
}

#[async_std::main]
async fn main() -> AnyResult<()> {
    pretty_env_logger::init();
    dotenv().ok();

    let arguments = Arguments::parse();
    let environments: Environments = from_env().map_err(|e| {
        error!("Failed to gather Twitter API key information: {}", e);
        e
    })?;
    debug!("Consumer Key: {}", environments.consumer_key);
    debug!("Consumer Secret: {}", environments.consumer_secret);
    debug!("Access Token: {}", environments.access_token);
    debug!("Access Token Secret: {}", environments.access_token_secret);

    let template: Template = {
        let mut reader = BufReader::new(File::open(&arguments.template_file).await?);
        let mut json = String::with_capacity(8192);
        reader.read_to_string(&mut json).await?;
        from_str(&json).map_err(|e| {
            error!("Failed to parse template file: {}", e);
            e
        })?
    };

    // OAuth パラメーターの生成
    let mut oauth_params = BTreeMap::new();
    oauth_params.insert("oauth_version", "1.0".to_owned());
    oauth_params.insert("oauth_signature_method".into(), "HMAC-SHA1".to_owned());
    oauth_params.insert("oauth_consumer_key", environments.consumer_key.clone());
    oauth_params.insert("oauth_token", environments.access_token.clone());
    oauth_params.insert("oauth_nonce", {
        // thread_rng() は cryptographically secure
        let mut rng = thread_rng();
        NONCE_CHARS.choose_multiple(&mut rng, 32).collect()
    });
    oauth_params.insert(
        "oauth_timestamp",
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(ts) => ts.as_secs().to_string(),
            Err(e) => {
                error!("Failed to get timestamp: {}", e);
                return Err(e.into());
            }
        },
    );

    // 通常パラメーターの生成
    let mut request_params = template.parameters.clone();
    for op in &arguments.parameters {
        let kv: Vec<_> = op.split('=').take(2).collect();
        match (kv.get(0), kv.get(1)) {
            (Some(&k), Some(&v)) if k != "" => {
                request_params.insert(k.into(), v.into());
            }
            _ => {
                warn!("Invalid parameter override detected, skipping...");
            }
        }
    }

    let mut request_params_str: Vec<_> = request_params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                match v {
                    Value::String(s) => utf8_percent_encode(&s, RFC3986_ESCAPES).to_string(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => unreachable!("Invalid data type"),
                }
            )
        })
        .chain(
            oauth_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, utf8_percent_encode(&v, RFC3986_ESCAPES))),
        )
        .collect();
    request_params_str.sort();

    // エンドポイント
    let endpoint_url = format!("https://api.twitter.com/1.1/{}", &template.endpoint);

    // シグネチャの生成
    let connected_params = request_params_str.join("&");
    let signature_base = format!(
        "{}&{}&{}",
        template.method.to_string(),
        utf8_percent_encode(&endpoint_url, RFC3986_ESCAPES),
        utf8_percent_encode(&connected_params, RFC3986_ESCAPES)
    );

    let signature_key = format!(
        "{}&{}",
        &environments.consumer_secret, &environments.access_token_secret
    );

    let mut hmac = HmacSha1::new_varkey(&signature_key.into_bytes()).expect("Should be accepted");
    hmac.update(&signature_base.into_bytes());
    let hmac_result = hmac.finalize().into_bytes();
    let encoded_signature = base64_encode(hmac_result);
    oauth_params.insert("oauth_signature", encoded_signature);

    debug!("OAuth parameters");
    for (key, value) in &oauth_params {
        debug!("{}: {}", key, value);
    }
    debug!("General parameters");
    for (key, value) in &request_params {
        debug!("{}: {}", key, value);
    }

    let oauth_header: Vec<_> = oauth_params
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, utf8_percent_encode(v, RFC3986_ESCAPES)))
        .collect();

    // 送信
    let request = match template.method {
        Method::Get => surf::get(endpoint_url),
        Method::Post => surf::post(endpoint_url),
        Method::Put => surf::put(endpoint_url),
        Method::Delete => surf::delete(endpoint_url),
    }
    .header(
        "Authorization",
        format!("OAuth {}", oauth_header.join(", ")),
    );

    let mut response = if request_params.is_empty() {
        request.await?
    } else {
        request.query(&request_params)?.await?
    };
    let body = response.body_string().await?;

    println!("{}", body);
    Ok(())
}
