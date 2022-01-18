import natsjwt


def test_returns_valid_seed():
    seed = natsjwt.generate_user_seed().decode("utf8")
    assert len(seed) == 58
    assert seed.startswith("S")
