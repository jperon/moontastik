ossl = require "openssl"
hmac = ossl.hmac
digest = ossl.digest

-- ############################################################################
-- # HKDF (HMAC-based Key Derivation Function)                                #
-- ############################################################################
HKDF_methods = {}

HKDF_methods.extract = (salt, ikm) =>
  -- HKDF-Extract(salt, IKM) -> PRK
  -- PRK = HMAC-Hash(salt, IKM)
  hmac.new(@_digest_name, salt)\final(ikm)

HKDF_methods.expand = (prk, info, length) =>
  -- HKDF-Expand(PRK, info, L) -> OKM
  h = hmac.new(@_digest_name, prk)
  hash_len = 32 if @_digest_name == "sha256" else 64
  n = math.ceil(length / hash_len)
  assert n <= 255, "Too much output length for HKDF"

  t, okm = "", ""
  for i = 1, n
    t = h\final(t .. info .. string.char(i))
    okm = okm .. t
  okm\sub 1, length

new = (digest_name) ->
  hkdf_obj = { _digest_name: digest_name\lower! }
  setmetatable hkdf_obj, { __index: HKDF_methods }
  hkdf_obj

:new
