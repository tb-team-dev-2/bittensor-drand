# Usage
Python package `bittensor_commit_reveal` has one function.

```python
from bittensor_commit_reveal import get_encrypted_commit
```

## Function docstring
The function could be considered like this:
```python
def get_encrypted_commit(
        uids: Union[NDArray[np.int64], "torch.LongTensor"], 
        weights: Union[NDArray[np.float32], "torch.FloatTensor"], 
        version_key: int, 
        subnet_reveal_period_epochs: int = 1, 
        block_time: int = 12, 
        tempo: int = 360
) -> tuple[bytes, int]:
"""Returns encrypted commit and target round for `commit_crv3_weights` extrinsic.

    Arguments:
        uids: The uids to commit.
        weights: The weights associated with the uids.
        version_key: The version key to use for committing and revealing. Default is `bittensor.core.settings.version_as_int`.
        subnet_reveal_period_epochs: Number of epochs after which the revive will be performed. Corresponds to hyperparameter 'commit_reveal_weights_interval' of the subnet. In epochs.
        block_time: Amount if seconds in one block. In seconds.
        tempo: Amount of blocks in one Epoch.
        
    Returns:
        commit (bites): hex value of encrypted and compressed uids and weights values for setting weights.
        target_round (int): Drand round number when weights have to be revealed. Based on Drand Quicknet network.
"""
# function logic
return commit, target_round
```


To test the function run in terminal:
```bash
mkdir test
cd test
python3 -m venv venv
. venv/bin/activate
pip install maturin bittensor ipython
cd ..

maturin develop
ipython

```

then copy-past to ipython
```python
import numpy as np
import bittensor_commit_reveal as crv3
from bittensor.utils.weight_utils import convert_weights_and_uids_for_emit

uids = [1, 3]
weights = [0.3, 0.7]
version_key = 843000

if isinstance(uids, list):
    uids = np.array(uids, dtype=np.int64)
if isinstance(weights, list):
    weights = np.array(weights, dtype=np.float32)

uids, weights = convert_weights_and_uids_for_emit(uids, weights)

print(crv3.get_encrypted_commit(uids, weights, version_key))
```
expected result
```python
(b'\xb9\x96\xe4\xd1\xfd\xabm\x8cc\xeb\xe3W\r\xc7J\xb4\xea\xa9\xd5u}OG~\xae\xcc\x9a@\xdf\xee\x16\xa9\x0c\x8d7\xd6\xea_c\xc2<\xcb\xa6\xbe^K\x97|\x16\xc6|;\xb5Z\x97\xc9\xb4\x8em\xf1hv\x16\xcf\xea\x1e7\xbe-Z\xe7e\x1f$\n\xf8\x08\xcb\x18.\x94V\xa3\xd7\xcd\xc9\x04F::\t)Z\xc6\xbey \x00\x00\x00\x00\x00\x00\x00\xaaN\xe8\xe97\x8f\x99\xbb"\xdf\xad\xf6\\#%\xca:\xc2\xce\xf9\x96\x9d\x8f\x9d\xa2\xad\xfd\xc73j\x16\xda \x00\x00\x00\x00\x00\x00\x00\x84*\xb0\rw\xad\xdc\x02o\xf7i)\xbb^\x99e\xe2\\\xee\x02NR+-Q\xcd \xf7\x02\x83\xffV>\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00\x00\x00\x00\x00*\x13wXb\x93\xc5"F\x17F\x05\xcd\x15\xb0=\xe2d\xfco3\x16\xfd\xe9\xc6\xbc\xd1\xb3Y\x97\xf9\xb9!\x01\x0c\x00\x00\x00\x00\x00\x00\x00X\xa2\x8c\x18Wkq\xe5\xe6\x1c2\x86\x08\x00\x00\x00\x00\x00\x00\x00AES_GCM_', 13300875)
```
