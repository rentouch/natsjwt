from natsjwt import NJWT

ACCOUNT_JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPUFRVTlpRRFBPSVhXS0FaN0JDUFFKV1JCN0dKVkg3SEZQU0ZWRTdXWE43M1RSQ1ZHRkxRIiwiaWF0IjoxNjQyMzIxMjM5LCJpc3MiOiJPQ0NYUkRaVlZHTVE2TUhMUUEzSE9SSzJNS05HV0E2NE1ONVY3VktDQUxZQU0ySkxFRUdWRk5CTiIsIm5hbWUiOiJyZW50b3VjaCIsInN1YiI6IkFDUzVZWFNLQURPTFJLSUNYNlBLQkpINU1NVUVSSFBLSzY0UlZYRTJYS1NQRFhDUVJINlROUkVUIiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaW1wb3J0cyI6LTEsImV4cG9ydHMiOi0xLCJ3aWxkY2FyZHMiOnRydWUsImNvbm4iOi0xLCJsZWFmIjotMX0sInJldm9jYXRpb25zIjp7IlVEUkEyWUxZNUlSVUdUTU41NjVMSDU2S0tSUzI3TU5NUTVPRkIzMzNHWE1RWFdRVFhUWllKNEFHIjoxNjQyMzIxMjM5fSwiZGVmYXVsdF9wZXJtaXNzaW9ucyI6eyJwdWIiOnt9LCJzdWIiOnt9fSwidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyfX0.TT2eyvb42YwrFylr1h7V4DlCqZl_5G_RjErbMh-XB99zomQoZk0GKfO29IQg5uedCv8lgT2-G_Vh5kkScb6rAw"
OPERATOR_SEED = b"SOACY3H75GCIIAYPLIJHCV3CTYDDA7NSTDOA37FGPZGBXD5GQ7ZMRYFB4Y"


# Create account nats JWT
account = NJWT.from_account_jwt(ACCOUNT_JWT)

# Change JWT, eg.g revoke a user
account.revoke("UB5BZ7SZRYTXQ5RJNWIMQ5FLD6656YMZIPDDK3PVXN5JTL664SEA62CX")

# print the complete, signed JWT
print(account.sign(OPERATOR_SEED))