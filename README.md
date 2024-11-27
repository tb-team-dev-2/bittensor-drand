run in terminal
```bash
mkdir test
cd test
python3 -m venv venv
. venv/bin/activate
pip install maturin ipython
cd ..

maturin develop
ipython

```

copy-past to ipython
```python
import bittensor_commit_reveal as cr

uids = [1, 3]
weights = [28086, 65535]
version_key = 840000
subnet_reveal_period_epochs = 1

print(cr.get_encrypted_commit(uids, weights, version_key, subnet_reveal_period_epochs))
```
