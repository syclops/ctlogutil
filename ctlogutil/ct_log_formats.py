from construct import (
    Bytes,
    Enum,
    GreedyRange,
    Int8ub,
    Int16ub,
    Int24ub,
    Int64ub,
    Struct,
    Switch,
    this,
)

LV16b = Struct(
    'length' / Int16ub,
    'value' / Bytes(this.length),
)

LV24b = Struct(
    'length' / Int24ub,
    'value' / Bytes(this.length),
)

LogEntryType = Enum(Int16ub, x509_entry=0, precert_entry=1)

ASN1Cert = LV24b

ASN1CertChain = LV24b

X509ChainEntry = Struct(
    'leaf_certificate' / ASN1Cert,
    'certificate_chain' / ASN1CertChain,
)

PrecertChainEntry = Struct(
    'leaf_certificate' / ASN1Cert,
    'certificate_chain' / ASN1CertChain,
)

LogEntry = Struct(
    'entry_type' / LogEntryType,
    'entry' / Switch(this.entry_type, {
        LogEntryType.x509_entry: X509ChainEntry,
        LogEntryType.precert_entry: PrecertChainEntry,
    }),
)

SignatureType = Enum(Int8ub, certificate_timestamp=0, tree_hash=1)

Version = Enum(Int8ub, v1=0)

LogID = Struct(
    'key_id' / Bytes(32),
)

TBSCertificate = LV24b

PreCert = Struct(
    'issuer_key_hash' / Bytes(32),
    'tbs_certificate' / TBSCertificate,
)

CtExtensions = LV16b

HashAlgorithm = Enum(Int8ub, none=0, md5=1, sha1=2, sha224=3, sha256=4,
                     sha384=5, sha512=6)

SignatureAlgorithm = Enum(Int8ub, anonymous=0, rsa=1, dsa=2, ecdsa=3)

SignatureAndHashAlgorithm = Struct(
    'hash' / HashAlgorithm,
    'signature' / SignatureAlgorithm,
)

DigitallySigned = Struct(
    'algorithm' / SignatureAlgorithm,
    'signature' / Struct(
        'length' / Int16ub,
        'data' / Bytes(this.length),
    ),
)

"""
In the following struct, the signature is of the following struct:
Struct(
    'sct_version' / Version,
    'signature_type' / SignatureType.certificate_timestamp,
    'timestamp' / Int64ub,
    'entry_type' / LogEntryType,
    'signed_entry' / Switch(this.entry_type, {
        LogEntryType.x509_entry: ASN1Cert,
        LogEntryType.precert_entry: PreCert,
    }),
    'extensions' / CtExtensions,
)
"""
SignedCertificateTimestamp = Struct(
    'sct_version' / Version,
    'id' / LogID,
    'timestamp' / Int64ub,
    'extensions' / CtExtensions,
    'signature' / DigitallySigned,
)

SerializedSCT = LV16b

SignedCertificateTimestampList = Struct(
    'sct_list' / GreedyRange(SerializedSCT),
)

MerkleLeafType = Enum(Int8ub, timestamped_entry=0)

TimestampedEntry = Struct(
    'timestamp' / Int64ub,
    'entry_type' / LogEntryType,
    'signed_entry' / Switch(this.entry_type, {
        LogEntryType.x509_entry: ASN1Cert,
        LogEntryType.precert_entry: PreCert,
    }),
    'extensions' / CtExtensions,
)

MerkleTreeLeaf = Struct(
    'version' / Version,
    'leaf_type' / MerkleLeafType,
    'timestamped_entry' / Switch(this.leaf_type, {
        MerkleLeafType.timestamped_entry: TimestampedEntry,
    }),
)
