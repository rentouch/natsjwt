import pytest
import natsjwt
from natsjwt import NJWT

ACCOUNT_SEED = b"SAAHUYEXZWLKAUAF3N3O2WE6GZQA4XMII7GR5SCMCIFBXATY5JJD5WYUBI"


@pytest.fixture
def user_seed(mocker):
    gen_user_seed = mocker.patch.object(natsjwt, "generate_user_seed")
    gen_user_seed.return_value = (
        b"SUAM26CS6JGHFNA63HSPTNXEMAQCF5MFX6VUIAZIE2QBIIOL5WJZVQ3EU4"
    )


def test_creates_basic_user(user_seed):
    user = NJWT.new_user("Peter", ACCOUNT_SEED)
    claim = user.claim
    assert claim["iss"] == "ACS5YXSKADOLRKICX6PKBJH5MMUERHPKK64RVXE2XKSPDXCQRH6TNRET"
    assert claim["name"] == "Peter"
    assert claim["sub"] == "UDRZHKCS6E647R37REDR3BMHQLCILU7QH6EUMXRXNOYO6WRYGLTOLYAE"
    assert claim["nats"] == {
        "pub": {},
        "sub": {},
        "subs": -1,
        "data": -1,
        "payload": -1,
        "bearer_token": True,
        "type": "user",
        "version": 2,
    }


def test_sets_expiry(user_seed):
    user = NJWT.new_user("Peter", ACCOUNT_SEED)
    user.expiry = 1642495509
    assert user.claim["exp"] == user.expiry


def test_sets_permissions(user_seed):
    user = NJWT.new_user("Peter", ACCOUNT_SEED)
    user.add_pub_allow("pubonly")
    user.add_sub_allow("subonly")
    user.add_pubsub_allow("both")
    assert user.claim["nats"]["sub"] == {"allow": ["subonly", "both"]}
    assert user.claim["nats"]["pub"] == {"allow": ["pubonly", "both"]}
