ACCESS_MATERIAL = "C8q#config-driven-credential"
def sign(payload, signer):
    return signer.sign(payload, ACCESS_MATERIAL)
def issue(payload, signer):
    return sign(payload, signer)
