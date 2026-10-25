//! Host names of item URLs: parsing, IDNA (punycode) and a small
//! registrable-domain heuristic.
//!
//! This is deliberately dependency-free so it compiles to WebAssembly. The
//! browser extension matches logins with the full Public Suffix List
//! (`tldts`); here a short list of common two-level suffixes and hosting
//! platforms is enough to group items and compare domains.

/// The parts of an item URL the analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// `http`, `https` or another scheme (lower case); `https` when missing.
    pub scheme: String,
    /// Lower-case ASCII host (punycode for international names).
    pub host: String,
    /// The host with punycode labels decoded, for display and lookalikes.
    pub unicode_host: String,
    /// Whether the scheme was written out (`http://…`) rather than assumed.
    pub explicit_scheme: bool,
}

/// Parses an item URL or bare host name (`github.com/login`). Returns `None`
/// for values without a usable host (notes, `android://` app links keep
/// their scheme and are returned, with the package name as host).
pub fn parse_url(value: &str) -> Option<ParsedUrl> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return None;
    }
    let (scheme, rest, explicit) = match value.find("://") {
        Some(at)
            if at > 0
                && value[..at]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) =>
        {
            (value[..at].to_ascii_lowercase(), &value[at + 3..], true)
        }
        _ => ("https".to_owned(), value, false),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let host = if authority.starts_with('[') {
        // IPv6 literal: keep it as it is.
        authority
            .split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default().to_owned()
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.contains(['\\', '%', '<', '>', '"']) {
        return None;
    }
    let (ascii, unicode) = idna_pair(&host)?;
    Some(ParsedUrl {
        scheme,
        host: ascii,
        unicode_host: unicode,
        explicit_scheme: explicit,
    })
}

/// Lower-case ASCII and Unicode forms of a host name.
pub fn idna_pair(host: &str) -> Option<(String, String)> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    let mut ascii = Vec::new();
    let mut unicode = Vec::new();
    for label in host.split('.') {
        if label.is_ascii() {
            ascii.push(label.to_owned());
            match label.strip_prefix("xn--") {
                Some(encoded) => unicode.push(punycode_decode(encoded)?),
                None => unicode.push(label.to_owned()),
            }
        } else {
            ascii.push(format!("xn--{}", punycode_encode(label)?));
            unicode.push(label.to_owned());
        }
    }
    Some((ascii.join("."), unicode.join(".")))
}

/// True for IPv4/IPv6 literals and `localhost`.
pub fn is_ip_or_local(host: &str) -> bool {
    host.starts_with('[')
        || host == "localhost"
        || host.ends_with(".localhost")
        || (host.split('.').count() == 4
            && host
                .split('.')
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit())))
}

/// Two-level public suffixes and hosting platforms whose subdomains belong
/// to different owners. Not complete; see the module documentation.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "ac.at",
    "co.at",
    "gv.at",
    "or.at",
    "com.au",
    "edu.au",
    "gov.au",
    "net.au",
    "org.au",
    "com.br",
    "net.br",
    "org.br",
    "co.ca",
    "com.cn",
    "net.cn",
    "org.cn",
    "com.co",
    "com.cy",
    "com.eg",
    "com.es",
    "com.gr",
    "com.hk",
    "co.hu",
    "co.id",
    "co.il",
    "ac.in",
    "co.in",
    "net.in",
    "org.in",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "com.mt",
    "com.mx",
    "com.my",
    "co.nz",
    "net.nz",
    "org.nz",
    "com.pe",
    "com.ph",
    "com.pk",
    "com.pl",
    "net.pl",
    "org.pl",
    "com.pt",
    "com.ro",
    "com.ru",
    "com.sa",
    "com.sg",
    "co.th",
    "in.th",
    "com.tr",
    "com.tw",
    "com.ua",
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "plc.uk",
    "com.ve",
    "com.vn",
    "co.za",
    "org.za",
    "com.ar",
    "com.ng",
    "co.ke",
    // Hosting platforms (private suffixes of the Public Suffix List).
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "azurewebsites.net",
    "cloudfront.net",
    "appspot.com",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "repl.co",
    "myshopify.com",
    "wordpress.com",
    "s3.amazonaws.com",
];

/// The registrable domain ("eTLD+1") of a lower-case host, or the host
/// itself for IP addresses, `localhost` and single labels.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.');
    if is_ip_or_local(host) {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_owned();
    }
    let take = |n: usize| labels[labels.len().saturating_sub(n)..].join(".");
    for suffix in MULTI_LABEL_SUFFIXES {
        let suffix_labels = suffix.split('.').count();
        if take(suffix_labels) == *suffix && labels.len() > suffix_labels {
            return take(suffix_labels + 1);
        }
    }
    take(2)
}

/// Splits a registrable domain into its first label and the suffix
/// (`paypal` and `com` for `paypal.com`, `bbc` and `co.uk` for `bbc.co.uk`).
pub fn split_label(registrable: &str) -> (&str, &str) {
    registrable.split_once('.').unwrap_or((registrable, ""))
}

// --- Punycode (RFC 3492) ------------------------------------------------------------

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(mut delta: u32, points: u32, first: bool) -> u32 {
    delta /= if first { DAMP } else { 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
}

fn digit_value(c: u8) -> Option<u32> {
    match c {
        b'a'..=b'z' => Some(u32::from(c - b'a')),
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 26),
        _ => None,
    }
}

fn digit_char(d: u32) -> char {
    // 0..25 = a..z, 26..35 = 0..9
    if d < 26 {
        char::from(b'a' + d as u8)
    } else {
        char::from(b'0' + (d - 26) as u8)
    }
}

/// Decodes a punycode label (without `xn--`).
pub fn punycode_decode(input: &str) -> Option<String> {
    let (basic, extended) = match input.rfind('-') {
        Some(at) => (&input[..at], &input[at + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut output: Vec<char> = basic.chars().collect();
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let bytes = extended.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = digit_value(*bytes.get(pos)?)?;
            pos += 1;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                T_MIN
            } else if k >= bias + T_MAX {
                T_MAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len = output.len() as u32 + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len)?;
        i %= len;
        output.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(output.into_iter().collect())
}

/// Encodes a Unicode label as punycode (without `xn--`).
pub fn punycode_encode(input: &str) -> Option<String> {
    let chars: Vec<u32> = input.chars().map(u32::from).collect();
    let mut output: String = input.chars().filter(char::is_ascii).collect();
    let basic = output.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while (handled as usize) < chars.len() {
        let m = *chars.iter().filter(|&&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &chars {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit_char(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_char(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls_and_bare_hosts() {
        let url = parse_url("HTTP://User@Accounts.Example.COM:8080/login?x#y").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "accounts.example.com");
        assert!(url.explicit_scheme);
        let bare = parse_url("github.com/login").unwrap();
        assert_eq!(bare.scheme, "https");
        assert_eq!(bare.host, "github.com");
        assert!(!bare.explicit_scheme);
        assert_eq!(parse_url(""), None);
        assert_eq!(parse_url("not a url"), None);
        assert_eq!(parse_url("https://[::1]:80/").unwrap().host, "[::1]");
    }

    #[test]
    fn punycode_round_trips() {
        // RFC 3492 sample and common IDNs.
        assert_eq!(punycode_encode("bücher").unwrap(), "bcher-kva");
        assert_eq!(punycode_decode("bcher-kva").unwrap(), "bücher");
        assert_eq!(punycode_encode("münchen").unwrap(), "mnchen-3ya");
        // "аpple" with a Cyrillic а.
        let encoded = punycode_encode("аpple").unwrap();
        assert_eq!(encoded, "pple-43d");
        assert_eq!(punycode_decode(&encoded).unwrap(), "аpple");
        let (ascii, unicode) = idna_pair("xn--pple-43d.com").unwrap();
        assert_eq!(ascii, "xn--pple-43d.com");
        assert_eq!(unicode, "аpple.com");
        assert_eq!(idna_pair("Bücher.de").unwrap().0, "xn--bcher-kva.de");
        assert_eq!(punycode_decode("ab!"), None);
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("accounts.google.com"), "google.com");
        assert_eq!(registrable_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("me.github.io"), "me.github.io");
        assert_eq!(registrable_domain("github.io"), "github.io");
        assert_eq!(registrable_domain("192.168.1.1"), "192.168.1.1");
        assert_eq!(registrable_domain("nas.localhost"), "nas.localhost");
        assert_eq!(split_label("bbc.co.uk"), ("bbc", "co.uk"));
    }
}
