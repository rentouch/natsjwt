import natsjwt
import nkeys

def test_returns_valid_seed():
    seed = natsjwt.generate_user_seed().decode("utf8")
    assert len(seed) == 58
    assert seed.startswith("S")


def test_validates_with_nkeys():
    user_seed = natsjwt.generate_user_seed()
    nkeys.from_seed(user_seed)