use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Connection {
    pub asn: Option<u64>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub domain: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpInfo {
    pub ip: String,
    pub success: bool,
    pub message: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub connection: Option<Connection>,
}
#[derive(Default)]
pub struct IpLookup {
    cache: Mutex<HashMap<IpAddr, (Instant, IpInfo)>>,
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && !(s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}
impl IpLookup {
    pub async fn lookup(&self, address: String) -> Result<IpInfo, String> {
        let ip: IpAddr = address.parse().map_err(|_| "Invalid IP address")?;
        if !public_ip(ip) {
            return Err("Only public unicast addresses can be looked up. Private/local addresses remain unknown.".into());
        }
        {
            let cache = self.cache.lock().map_err(|e| e.to_string())?;
            if let Some((time, info)) = cache.get(&ip) {
                if time.elapsed() < Duration::from_secs(86400) {
                    return Ok(info.clone());
                }
            }
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let mut response = client
            .get(format!("https://ipwho.is/{ip}"))
            .send()
            .await
            .map_err(|e| format!("IP lookup unavailable: {e}"))?
            .error_for_status()
            .map_err(|e| format!("IP lookup failed (possibly rate limited): {e}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > 65536 {
                return Err("IP lookup response exceeded limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        let info: IpInfo =
            serde_json::from_slice(&body).map_err(|e| format!("Invalid lookup response: {e}"))?;
        if !info.success {
            return Err(info
                .message
                .unwrap_or("Lookup provider could not resolve this IP".into()));
        }
        if info.ip.parse::<IpAddr>().ok() != Some(ip) {
            return Err("Lookup returned a different IP address".into());
        }
        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        if cache.len() >= 128 {
            cache.clear();
        }
        cache.insert(ip, (Instant::now(), info.clone()));
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup_excludes_local_and_reserved_ranges() {
        for ip in [
            "192.168.1.67",
            "100.64.1.1",
            "127.0.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2400:1a00:3b85:825e:1560:57fb:ee7d:ab43"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
    }
}
