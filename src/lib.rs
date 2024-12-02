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

#[derive(Encode)]
pub struct WeightsTlockPayload {
    pub uids: Vec<u16>,
    pub values: Vec<u16>,
    pub version_key: u64,
}

async fn generate_commit(
    uids: Vec<u16>,
    values: Vec<u16>,
    version_key: u64,
    subnet_reveal_period_epochs: u64,
    block_time: u64,
    tempo: u64,
) -> Result<(Vec<u8>, u64), (std::io::Error, String)> {
    // Steps comes from here https://github.com/opentensor/subtensor/pull/982/files#diff-7261bf1c7f19fc66a74c1c644ec2b4b277a341609710132fb9cd5f622350a6f5R120-R131
    // 1 Instantiate payload
    let payload = WeightsTlockPayload {
        uids,
        values,
        version_key,
    };

    // 2 Serialize payload
    let serialized_payload = payload.encode();

    // Calculate reveal_round
    // all of 3 variables are constants for drand quicknet
    let period = 3;
    let genesis_time = 1692803367;
    let public_key = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current_round = (now - genesis_time) / period;
    // tempo is amount of blocks in 1 epoch
    // block_time is length the block in seconds
    // subnet_reveal_period_epochs means after how many epochs to make a commit reveal
    let delay_seconds = tempo * block_time * subnet_reveal_period_epochs;
    let rounds_to_wait = (delay_seconds + period - 1) / period;
    let reveal_round = current_round + rounds_to_wait;

    // 3 Encrypt
    let pub_key_bytes = hex::decode(public_key).expect("Decoding failed");
    let pub_key =
        <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(&*pub_key_bytes).unwrap();

    // 4 Create identity
    let message = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(reveal_round.to_be_bytes());
        hasher.finalize().to_vec()
    };
    let identity = Identity::new(b"", vec![message]);

    // 5. Encryption via tle with t-lock under the hood
    let esk = [2; 32];
    let ct = tle::<TinyBLS381, AESGCMStreamCipherProvider, OsRng>(
        pub_key,
        esk,
        &serialized_payload,
        identity,
        OsRng,
    )
    .map_err(|_| PyErr::new::<PyValueError, _>("Encryption failed."))
    .unwrap();

    // 6. Compress ct
    let mut ct_bytes: Vec<u8> = Vec::new();

    ct.serialize_compressed(&mut ct_bytes)
        .map_err(|_| PyErr::new::<PyValueError, _>("Ciphertext serialization failed."))
        .unwrap();

    // 7. Return result
    Ok((ct_bytes, reveal_round))
}

#[pyfunction]
#[pyo3(signature = (uids, weights, version_key, subnet_reveal_period_epochs=1, block_time=12, tempo=360))]
fn get_encrypted_commit(
    py: Python,
    uids: Vec<u16>,
    weights: Vec<u16>,
    version_key: u64,
    subnet_reveal_period_epochs: u64,
    block_time: u64,
    tempo: u64,
) -> PyResult<(Py<PyBytes>, u64)> {
    // create runtime to make async call
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| PyValueError::new_err(e.to_string()))?;
    let result = runtime.block_on(generate_commit(
        uids,
        weights,
        version_key,
        subnet_reveal_period_epochs,
        block_time,
        tempo,
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

#[pymodule]
fn bittensor_commit_reveal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_encrypted_commit, m)?)?;
    Ok(())
}
