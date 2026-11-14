//! Why a certificate could not be obtained, read or written.

/// Why provisioning failed, in words a log line and an operator read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionError {
    /// What was wrong.
    pub message: String,
}

impl ProvisionError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for ProvisionError {}

/// DER that is not what X.509 or PKCS #10 says.
impl From<asn1::Asn1Error> for ProvisionError {
    fn from(error: asn1::Asn1Error) -> Self {
        Self::new(format!("the DER: {}", error.message))
    }
}

/// A certificate that does not read (`xmip-core-library-tls`).
impl From<tls::TlsError> for ProvisionError {
    fn from(error: tls::TlsError) -> Self {
        Self::new(error.message)
    }
}

/// Base64 or PEM that is not what it claims.
impl From<codec::CodecError> for ProvisionError {
    fn from(error: codec::CodecError) -> Self {
        Self::new(error.message)
    }
}
