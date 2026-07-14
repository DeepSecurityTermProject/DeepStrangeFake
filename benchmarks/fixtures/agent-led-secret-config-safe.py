import os
ACCESS_MATERIAL = os.environ.get("ACCESS_MATERIAL")
def sign(payload, signer):
    return signer.sign(payload, ACCESS_MATERIAL)
def issue(payload, signer):
    return sign(payload, signer)
