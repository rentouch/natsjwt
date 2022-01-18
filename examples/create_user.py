import time
from natsjwt import NJWT

ACCOUNT_SEED = b"SAAHUYEXZWLKAUAF3N3O2WE6GZQA4XMII7GR5SCMCIFBXATY5JJD5WYUBI"

# Create new user with expiry and pubsub rule
user_jwt = NJWT.new_user("Peter", ACCOUNT_SEED)
user_jwt.expiry = int(time.time() + 60 * 15)  # expires in 15 minutes
user_jwt.add_pubsub_allow("foo.bar")  # allowed to publish and subscribe on foo.bar
print(user_jwt.sign())
