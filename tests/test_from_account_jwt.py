import time
from natsjwt import NJWT

ACCOUNT_JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPUFRVTlpRRFBPSVhXS0FaN0JDUFFKV1JCN0dKVkg3SEZQU0ZWRTdXWE43M1RSQ1ZHRkxRIiwiaWF0IjoxNjQyMzIxMjM5LCJpc3MiOiJPQ0NYUkRaVlZHTVE2TUhMUUEzSE9SSzJNS05HV0E2NE1ONVY3VktDQUxZQU0ySkxFRUdWRk5CTiIsIm5hbWUiOiJyZW50b3VjaCIsInN1YiI6IkFDUzVZWFNLQURPTFJLSUNYNlBLQkpINU1NVUVSSFBLSzY0UlZYRTJYS1NQRFhDUVJINlROUkVUIiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaW1wb3J0cyI6LTEsImV4cG9ydHMiOi0xLCJ3aWxkY2FyZHMiOnRydWUsImNvbm4iOi0xLCJsZWFmIjotMX0sInJldm9jYXRpb25zIjp7IlVEUkEyWUxZNUlSVUdUTU41NjVMSDU2S0tSUzI3TU5NUTVPRkIzMzNHWE1RWFdRVFhUWllKNEFHIjoxNjQyMzIxMjM5fSwiZGVmYXVsdF9wZXJtaXNzaW9ucyI6eyJwdWIiOnt9LCJzdWIiOnt9fSwidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyfX0.TT2eyvb42YwrFylr1h7V4DlCqZl_5G_RjErbMh-XB99zomQoZk0GKfO29IQg5uedCv8lgT2-G_Vh5kkScb6rAw"
OPERATOR_SEED = b"SOACY3H75GCIIAYPLIJHCV3CTYDDA7NSTDOA37FGPZGBXD5GQ7ZMRYFB4Y"


def test_returns_correct_signature(mocker):
    expected_jwt = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiAiR000R0daSldHVTNUU1lSWUc1UVRRTUJUSEVZR01ZVEVNTlJEU05UR0dJWkRPWkJaR0FaR01ZSlpHTTNUT01UR0dBWUdHWTNCR1UzVE9NTERHNDNHTU5CWk1NNERPTkRETUZRVEVNWSIsICJpYXQiOiAxNjQyNDkzMjQxLCAiaXNzIjogIk9DQ1hSRFpWVkdNUTZNSExRQTNIT1JLMk1LTkdXQTY0TU41VjdWS0NBTFlBTTJKTEVFR1ZGTkJOIiwgIm5hbWUiOiAicmVudG91Y2giLCAic3ViIjogIkFDUzVZWFNLQURPTFJLSUNYNlBLQkpINU1NVUVSSFBLSzY0UlZYRTJYS1NQRFhDUVJINlROUkVUIiwgIm5hdHMiOiB7ImxpbWl0cyI6IHsic3VicyI6IC0xLCAiZGF0YSI6IC0xLCAicGF5bG9hZCI6IC0xLCAiaW1wb3J0cyI6IC0xLCAiZXhwb3J0cyI6IC0xLCAid2lsZGNhcmRzIjogdHJ1ZSwgImNvbm4iOiAtMSwgImxlYWYiOiAtMX0sICJyZXZvY2F0aW9ucyI6IHsiVURSQTJZTFk1SVJVR1RNTjU2NUxINTZLS1JTMjdNTk1RNU9GQjMzM0dYTVFYV1FUWFRaWUo0QUciOiAxNjQyMzIxMjM5fSwgImRlZmF1bHRfcGVybWlzc2lvbnMiOiB7InB1YiI6IHt9LCAic3ViIjoge319LCAidHlwZSI6ICJhY2NvdW50IiwgInZlcnNpb24iOiAyfX0.boIKBS-emBFna_lpEZbhfDEAzI_U84vGfWsq8z5acV-O3TZM31NYWtHtS5wMSHe2TLbBRYGSjb3nphgZNucoAQ"
    mocker.patch.object(time, "time", return_value=1642493241.380353)
    account = NJWT.from_account_jwt(ACCOUNT_JWT)
    signed = account.sign(OPERATOR_SEED)
    assert signed == expected_jwt