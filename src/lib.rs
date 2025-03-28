use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use codec::Encode;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::OsRng;
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use tle::{
    curves::drand::TinyBLS381, ibe::fullident::Identity,
    stream_ciphers::AESGCMStreamCipherProvider, tlock::tle,
};
use tokio;
use w3f_bls::EngineBLS;

pub const SUBTENSOR_PULSE_DELAY: u64 = 24; //Drand rounds amount
const PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const GENESIS_TIME: u64 = 1692803367;
const DRAND_PERIOD: u64 = 3;

#[derive(Encode)]
pub struct WeightsTlockPayload {
    pub uids: Vec<u16>,
    pub values: Vec<u16>,
    pub version_key: u64,
}

/// Encrypts and compresses the provided serialized data for secure transfer.
///
/// # Arguments
///
/// * `serialized_data` - A slice of bytes containing the serialized data to be encrypted.
/// * `reveal_round` - A `u64` value representing the round during which the encryption will be revealed.
///
/// # Returns
///
/// Returns a `Result` which is:
/// * `Ok(Vec<u8>)` containing the compressed and encrypted bytes if the process succeeds.
/// * `Err((std::io::Error, String))` if an error occurs during decoding, public key deserialization,
///   encryption, or ciphertext compression.
///
/// # Example
///
/// ```rust
/// let serialized_data = b"example_data";
/// let reveal_round = 42;
/// match encrypt_and_compress(serialized_data, reveal_round) {
///     Ok(encrypted_data) => {
///         println!("Encrypted and compressed data: {:?}", encrypted_data);
///     }
///     Err((err, message)) => {
///         eprintln!("Error: {}, Message: {}", err, message);
///     }
/// }
/// ```
fn encrypt_and_compress(
    serialized_data: &[u8],
    reveal_round: u64,
) -> Result<Vec<u8>, (std::io::Error, String)> {
    // Deserialize public key
    let pub_key_bytes = hex::decode(PUBLIC_KEY).map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)),
            "Decoding public key failed.".to_string(),
        )
    })?;
    let pub_key =
        <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(&*pub_key_bytes)
            .map_err(|e| {
                (
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)),
                    "Deserializing public key failed.".to_string(),
                )
            })?;

    // Create identity from reveal_round
    let message = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(reveal_round.to_be_bytes());
        hasher.finalize().to_vec()
    };
    let identity = Identity::new(b"", vec![message]);

    // Encrypt payload
    let esk = [2; 32];
    let ct = tle::<TinyBLS381, AESGCMStreamCipherProvider, OsRng>(
        pub_key,
        esk,
        &serialized_data,
        identity,
        OsRng,
    )
    .map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)),
            "Encryption failed.".to_string(),
        )
    })?;

    // Compress ciphertext
    let mut ct_bytes: Vec<u8> = Vec::new();
    ct.serialize_compressed(&mut ct_bytes).map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)),
            "Ciphertext serialization failed.".to_string(),
        )
    })?;

    Ok(ct_bytes)
}

/// Generates a commit containing a payload to be encrypted and information about the reveal round,
/// along with the timestamped reveal round for the network.
///
/// # Arguments
///
/// * `uids` - A vector of unique identifiers (UIDs).
/// * `values` - A vector of associated values for the UIDs.
/// * `version_key` - A u64 value representing the version key for the commit.
/// * `tempo` - A u64 specifying the tempo (block interval) for the network.
/// * `current_block` - The current block number as u64.
/// * `netuid` - A u16 representing the network's unique identifier.
/// * `subnet_reveal_period_epochs` - A u64 indicating the number of epochs before reveal.
/// * `block_time` - Duration of each block in seconds as u64.
///
/// # Returns
///
/// A `Result` which is:
/// * `Ok((Vec<u8>, u64))` containing the encrypted commit payload and the calculated reveal round timestamp if successful.
/// * `Err((std::io::Error, String))` if an error occurs during payload serialization, encryption, or other processing steps.
async fn generate_commit(
    uids: Vec<u16>,
    values: Vec<u16>,
    version_key: u64,
    tempo: u64,
    current_block: u64,
    netuid: u16,
    subnet_reveal_period_epochs: u64,
    block_time: f64,
) -> Result<(Vec<u8>, u64), (std::io::Error, String)> {
    // Steps comes from here https://github.com/opentensor/subtensor/pull/982/files#diff-7261bf1c7f19fc66a74c1c644ec2b4b277a341609710132fb9cd5f622350a6f5R120-R131

    // Instantiate payload
    let payload = WeightsTlockPayload {
        uids,
        values,
        version_key,
    };
    let serialized_payload = payload.encode();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let tempo_plus_one = tempo + 1;
    let netuid_plus_one = (netuid as u64) + 1;
    let block_with_offset = current_block + netuid_plus_one;
    let current_epoch = block_with_offset / tempo_plus_one;

    let mut reveal_epoch = current_epoch + subnet_reveal_period_epochs;
    let mut reveal_block_number = reveal_epoch * tempo_plus_one - netuid_plus_one;
    let mut blocks_until_reveal = reveal_block_number - current_block;
    let mut time_until_reveal = (blocks_until_reveal as f64) * block_time;

    //
    while time_until_reveal < (SUBTENSOR_PULSE_DELAY * DRAND_PERIOD) as f64 {
        reveal_epoch += 1;
        reveal_block_number = reveal_epoch * tempo_plus_one - netuid_plus_one;
        blocks_until_reveal = reveal_block_number - current_block;
        time_until_reveal = (blocks_until_reveal as f64) * block_time;
    }

    let reveal_time = now + time_until_reveal;
    let reveal_round = ((reveal_time - GENESIS_TIME as f64) / DRAND_PERIOD as f64).ceil() as u64
        - SUBTENSOR_PULSE_DELAY;

    let ct_bytes = encrypt_and_compress(&serialized_payload, reveal_round)?;

    Ok((ct_bytes, reveal_round))
}

#[pyfunction]
#[pyo3(signature = (uids, weights, version_key, tempo, current_block, netuid, subnet_reveal_period_epochs, block_time=12.0))]
fn get_encrypted_commit(
    py: Python,
    uids: Vec<u16>,
    weights: Vec<u16>,
    version_key: u64,
    tempo: u64,
    current_block: u64,
    netuid: u16,
    subnet_reveal_period_epochs: u64,
    block_time: f64,
) -> PyResult<(Py<PyBytes>, u64)> {
    // create runtime to make async call
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| PyValueError::new_err(e.to_string()))?;
    let result = runtime.block_on(generate_commit(
        uids,
        weights,
        version_key,
        tempo,
        current_block,
        netuid,
        subnet_reveal_period_epochs,
        block_time,
    ));
    // matching the result
    match result {
        Ok((ciphertext, target_round)) => {
            let py_bytes = PyBytes::new_bound(py, &ciphertext).into();
            Ok((py_bytes, target_round))
        }
        Err(e) => Err(PyValueError::new_err(format!("{:?}", e))),
    }
}

async fn encrypt_commitment(
    data: &str,
    blocks_until_reveal: u64,
    block_time: f64,
) -> Result<(Vec<u8>, u64), (std::io::Error, String)> {
    let serialized_data = data.encode();

    // revealed round calculation
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let reveal_round = ((now - GENESIS_TIME)
        + (blocks_until_reveal as f64 * block_time).round() as u64)
        / DRAND_PERIOD;

    // TLE encoding
    let ct_bytes = encrypt_and_compress(&serialized_data, reveal_round).map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)),
            "Encryption failed.".to_string(),
        )
    })?;

    Ok((ct_bytes, reveal_round))
}

#[pyfunction]
#[pyo3(signature = (data, blocks_until_reveal, block_time=12.0))]
fn get_encrypted_commitment(
    py: Python,
    data: &str,
    blocks_until_reveal: u64,
    block_time: f64,
) -> PyResult<(Py<PyBytes>, u64)> {
    // create runtime to make async call
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| PyValueError::new_err(e.to_string()))?;
    let result = runtime.block_on(encrypt_commitment(data, blocks_until_reveal, block_time));
    // matching the result
    match result {
        Ok((ciphertext, target_round)) => {
            let py_bytes = PyBytes::new_bound(py, &ciphertext).into();
            Ok((py_bytes, target_round))
        }
        Err(e) => Err(PyValueError::new_err(format!("{:?}", e))),
    }
}

#[pymodule]
fn bittensor_commit_reveal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_encrypted_commit, m)?)?;
    m.add_function(wrap_pyfunction!(get_encrypted_commitment, m)?)?;
    Ok(())
}
