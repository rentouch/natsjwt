# NATS JWT

## Requirements / Installation
You need to have the `nsc` tool [https://github.com/nats-io/nsc] installed on 
your machine as generating new user-seeds is not implemented in Python yet.


## Examples

Create a new user JWT
```
user_jwt = NJWT.new_user("user-name")
print(account_jwt.sing(b"SAAHUYE..."))
```

Do changes to an existing JWT
```
account_jwt = NJWT.from_account_jwt("eyJ0eXAiOiJ...")
account_jwt.revoke("UB5BZ7SZ...")
print(account_jwt.sing(b"SAAHUYEX..."))
```

More can be found in `./examples` directory of this project.


## Development of this package

Installation
1. Make sure that you have poetry installed
2. `poetry install`
3. Set dev mode `poetry run pip install -e .`

Run the tests  
`poetry run pytest tests`

Run examples  
E.g. `poetry run python examples/re-issue-account-jwt.py`


### Publishing to PyPI
1. `poetry build`
2. tbd