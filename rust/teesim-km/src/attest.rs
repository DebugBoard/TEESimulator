// Attestation signing keys loaded from a keybox.xml.
//
// Implements the TA's `RetrieveCertSigningInfo` trait so that generated keys are
// attested with the batch keys from the configured keybox. A factory batch keybox
// carries both an RSA and an EC key and each attested key is signed with the matching
// algorithm; an RKP-extracted keybox carries only an EC P-256 key, so every leaf
// (RSA keys included) is signed with the EC key, exactly as a real RKP device does.
// At least one key must be present, but neither is individually required: a <Key> whose private key
// is in no format we can sign with is dropped like an absent one, so its leaves fall back to the
// other key rather than every request for that algorithm failing.
//
// A keybox's PEM is taken as it comes — PKCS#8 or the bare algorithm structure — and unwrapped to the
// bare structure the TA's key material is defined as (see `key_material`).

use base64::{engine::general_purpose, Engine as _};
use kmr_common::{
    crypto::ec, crypto::rsa, crypto::CurveType, crypto::KeyMaterial, Error,
};
use kmr_ta::device::{RetrieveCertSigningInfo, SigningAlgorithm, SigningKeyType};
use kmr_wire::keymint::{self, EcCurve};
use roxmltree::Document;

/// Per-algorithm signing key material plus its certificate chain.
#[derive(Clone)]
struct AlgoInfo {
    key: KeyMaterial,
    chain: Vec<keymint::Certificate>,
}

/// Signing information for the asymmetric key types we attest with. Each algorithm is optional; a
/// keybox must carry at least one usable key, but an RKP-extracted keybox legitimately has only the
/// EC key.
#[derive(Clone)]
pub struct CertSignInfo {
    rsa: Option<AlgoInfo>,
    ec: Option<AlgoInfo>,
}

impl CertSignInfo {
    /// Choose the batch key for an attested key, preferring the matching algorithm (`prefer_ec`) and
    /// falling back to the other key when the keybox lacks the preferred one. Returns the key info
    /// plus whether the chosen key is EC, so callers stamp the signature fields for the key that
    /// actually signs rather than the key being attested. `new` guarantees at least one key exists,
    /// so the fallback is always present.
    fn pick(&self, prefer_ec: bool) -> (&AlgoInfo, bool) {
        let (primary, other) = if prefer_ec { (&self.ec, &self.rsa) } else { (&self.rsa, &self.ec) };
        match primary {
            Some(a) => (a, prefer_ec),
            None => (
                other.as_ref().expect("keybox has at least one signing key"),
                !prefer_ec,
            ),
        }
    }

    /// The batch signing key, its keybox certificate chain, and whether that key is EC. `prefer_ec`
    /// requests the algorithm matching the key being attested; when absent, the other key is used
    /// (an EC-only RKP keybox signs every leaf with its EC key). Patch mode re-signs a real
    /// attestation leaf with this key and appends this chain.
    pub fn batch(&self, prefer_ec: bool) -> (KeyMaterial, &[keymint::Certificate], bool) {
        let (a, is_ec) = self.pick(prefer_ec);
        (a.key.clone(), &a.chain, is_ec)
    }
}

impl CertSignInfo {
    /// Parse a keybox.xml string and extract whichever of the RSA and EC signing keys/chains it
    /// carries. Requires at least one; a factory keybox has both, an RKP-extracted keybox only EC.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        let doc = Document::parse(keybox_xml).map_err(|e| format!("keybox parse: {e:?}"))?;

        let node = |algo: &str| {
            doc.descendants()
                .find(|n| n.has_tag_name("Key") && n.attribute("algorithm") == Some(algo))
        };

        // `parse_algo` yields `None` for a <Key> whose private key we cannot sign with, so such a
        // keybox still loads with the algorithm it does have.
        let rsa = node("rsa").map(|n| parse_algo(n, SigningAlgorithm::Rsa)).transpose()?.flatten();
        let ec = node("ecdsa").map(|n| parse_algo(n, SigningAlgorithm::Ec)).transpose()?.flatten();

        if rsa.is_none() && ec.is_none() {
            return Err(
                "keybox: no usable <Key algorithm=\"rsa\"> or <Key algorithm=\"ecdsa\">".to_string()
            );
        }

        let info = CertSignInfo { rsa, ec };
        log::info!(
            "teesim_km: keybox parsed (rsa={}, ec={})",
            info.rsa.is_some(),
            info.ec.is_some()
        );
        if let Some(a) = &info.rsa {
            crate::resign::log_chain("teesim_km: keybox RSA chain", &a.chain);
        }
        if let Some(a) = &info.ec {
            crate::resign::log_chain("teesim_km: keybox EC chain", &a.chain);
        }
        Ok(info)
    }
}

fn parse_algo(node: roxmltree::Node, algo: SigningAlgorithm) -> Result<Option<AlgoInfo>, String> {
    let name = match algo {
        SigningAlgorithm::Rsa => "RSA",
        SigningAlgorithm::Ec => "EC",
    };

    let priv_pem = node
        .children()
        .find(|n| n.has_tag_name("PrivateKey"))
        .ok_or_else(|| format!("{name}: missing PrivateKey"))?
        .text()
        .ok_or_else(|| format!("{name}: empty PrivateKey"))?;
    let key_der = decode_pem(priv_pem)?;

    let mut chain = Vec::new();
    for cert in node.descendants().filter(|n| n.has_tag_name("Certificate")) {
        let pem = cert.text().ok_or_else(|| format!("{name}: empty Certificate"))?;
        chain.push(keymint::Certificate { encoded_certificate: decode_pem(pem)? });
    }
    if chain.len() < 2 {
        return Err(format!("{name}: expected at least 2 certificates, found {}", chain.len()));
    }

    let (key, format) = match key_material(algo, &key_der) {
        Ok(k) => k,
        // The chain and the XML are well-formed; only the private key is not something we can sign
        // with. Drop the algorithm instead of failing the whole keybox: `pick` then signs every leaf
        // with the other key (what an EC-only RKP keybox already does), which keeps attestation
        // working rather than failing every request for this algorithm at generateKey time.
        Err(e) => {
            log::warn!(
                "teesim_km: keybox {name} key unusable ({e}); ignoring it — leaves that would be \
                 signed with it fall back to the keybox's other key"
            );
            return Ok(None);
        }
    };
    log::info!("teesim_km: keybox {name} key loaded from {format}, {} cert(s)", chain.len());
    Ok(Some(AlgoInfo { key, chain }))
}

/// Turn a keybox private key's DER into the TA's key material.
///
/// A keybox ships whatever PEM its issuer wrote: a factory keybox's RSA key is a PKCS#8
/// `PrivateKeyInfo` (`-----BEGIN PRIVATE KEY-----`) while its EC key is a bare SEC1 `ECPrivateKey`
/// (`-----BEGIN EC PRIVATE KEY-----`), and either algorithm is also found in the other form. The TA's
/// key material is always the *bare* algorithm structure — `rsa::Key` is a PKCS#1 `RSAPrivateKey` and
/// `ec::NistKey` a SEC1 `ECPrivateKey`, which is what BoringSSL's `d2i_RSAPrivateKey` /
/// `EC_KEY_parse_private_key` accept — so a PKCS#8 key must be unwrapped here. Handing the wrapper
/// through as-is parses at no point later: the failure surfaces only when the batch key is first used,
/// i.e. as every attested key of that algorithm failing to generate. Returns the material and the
/// format it was found in, which the caller logs so the keybox's shape is visible without a device.
fn key_material(algo: SigningAlgorithm, der: &[u8]) -> Result<(KeyMaterial, &'static str), String> {
    match algo {
        SigningAlgorithm::Rsa => {
            // PKCS#8 first (the common keybox form), then a bare PKCS#1 RSAPrivateKey. Both parses
            // validate the structure, so an unusable key is rejected here rather than at signing time.
            if let Ok((key, _, _)) = rsa::import_pkcs8_key(der) {
                return Ok((key, "PKCS#8"));
            }
            rsa::import_pkcs1_key(der)
                .map(|(key, _, _)| (key, "PKCS#1"))
                .map_err(|e| format!("neither a PKCS#8 nor a PKCS#1 RSA private key: {e:?}"))
        }
        SigningAlgorithm::Ec => {
            // A PKCS#8 EC key names its curve in the algorithm parameters, so take the curve from
            // there rather than assuming one.
            match ec::import_pkcs8_key(der) {
                Ok(key @ KeyMaterial::Ec(_, CurveType::Nist, _)) => Ok((key, "PKCS#8")),
                Ok(_) => Err("EC key is not on a NIST curve".to_string()),
                // Not PKCS#8: a bare SEC1 ECPrivateKey, the form keyboxes in the field ship. They use
                // NIST P-256 for the batch key, and the structure's optional curve parameters are
                // often absent, so P-256 is assumed exactly as it always has been.
                Err(_) => Ok((
                    KeyMaterial::Ec(
                        EcCurve::P256,
                        CurveType::Nist,
                        ec::Key::P256(ec::NistKey(der.to_vec())).into(),
                    ),
                    "SEC1 (assumed P-256)",
                )),
            }
        }
    }
}

/// Strip PEM armor and all whitespace, then base64-decode.
fn decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    let mut b64 = String::with_capacity(pem.len());
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        b64.extend(line.chars().filter(|c| !c.is_whitespace()));
    }
    general_purpose::STANDARD.decode(&b64).map_err(|e| format!("base64: {e:?}"))
}

impl RetrieveCertSigningInfo for CertSignInfo {
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        // kmr-ta derives the leaf's signature algorithm from the returned key material, so the EC
        // fallback for an RSA request on an EC-only keybox yields a correctly EC-signed leaf.
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.key.clone())
    }

    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.chain.clone())
    }
}
