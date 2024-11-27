use w3f_bls::EngineBLS;

use tle::{
    curves::drand::TinyBLS381, ibe::fullident::Identity,
    stream_ciphers::AESGCMStreamCipherProvider, tlock::tle,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use serde::{Deserialize, Serialize};

use codec::Encode;
use reqwest::Client;
use tokio;

#[derive(Debug, Deserialize)]
struct DrandInfo {
    public_key: String,
    period: u64,
    genesis_time: u64,
    // hash: String,
    // #[serde(rename = "groupHash")]
    // group_hash: String,
    // #[serde(rename = "schemeID")]
    // scheme_id: String,
    // metadata: Metadata,
}

// #[derive(Debug, Deserialize)]
// struct Metadata {
//     #[serde(rename = "beaconID")]
//     beacon_id: String,
// }

#[derive(Encode)]
pub struct WeightsTlockPayload {
    pub uids: Vec<u16>,
    pub values: Vec<u16>,
    pub version_key: u64,
}

#[derive(Serialize, Deserialize)]
struct SerializableCiphertext {
    round: u64,
    u: Vec<u8>,
    v: Vec<u8>,
    w: Vec<u8>,
}

async fn fetch_drand_info(api_url: &str) -> Result<DrandInfo, (std::io::Error, String)> {
    let client = Client::new();
    let response = client
        .get(api_url)
        .send()
        .await
        .unwrap()
        .json::<DrandInfo>()
        .await
        .unwrap();
    Ok(response)
}

async fn generate_commit(
    uids: Vec<u16>,
    values: Vec<u16>,
    version_key: u64,
    subnet_reveal_period_epochs: u64,
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

    // fetching drand data (quicknet)
    let url = "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info";
    let info = fetch_drand_info(url).await?;

    // Calculate reveal_round
    let period = info.period;
    let genesis_time = info.genesis_time;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_round = ((now - genesis_time) / period) + 1;
    let delay_seconds = 360 * 12 * subnet_reveal_period_epochs;
    let rounds_to_wait = (delay_seconds + period - 1) / period;
    let reveal_round = current_round + rounds_to_wait;

    // 3 Encrypt
    let pub_key_bytes = hex::decode(info.public_key).expect("Decoding failed");
    let pub_key =
        <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(&*pub_key_bytes).unwrap();

    // 4 Create identity
    let message = {
        let mut hasher = Sha256::new();
        hasher.update(reveal_round.to_be_bytes());
        hasher.finalize().to_vec()
    };
    let identity = Identity::new(b"", vec![message]);

    // 5. Encryption
    let rng = ChaCha20Rng::seed_from_u64(0);
    let esk = [2; 32];
    let ct = tle::<TinyBLS381, AESGCMStreamCipherProvider, ChaCha20Rng>(
        pub_key,
        esk,
        &serialized_payload,
        identity,
        rng,
    )
    .unwrap();

    // 6. Compress ct
    let mut compressed = Vec::new();
    ct.serialize_compressed(&mut compressed).unwrap();

    // 7. Return result
    Ok((compressed, reveal_round))
}

#[pyfunction]
fn get_encrypted_commit(
    py: Python,
    uids: Vec<u16>,
    weights: Vec<u16>,
    version_key: u64,
    subnet_reveal_period_epochs: u64,
) -> PyResult<(Py<PyBytes>, u64)> {
    // create runtime to make async call
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| PyValueError::new_err(e.to_string()))?;
    let result = runtime.block_on(generate_commit(
        uids,
        weights,
        version_key,
        subnet_reveal_period_epochs,
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
