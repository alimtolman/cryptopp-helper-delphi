unit CryptoPP_Lib;

interface

const
  DllName = 'cryptopp.dll';

{$region 'helpers'}

(**
 * Delete allocated in library byte array
 *
 * @note byte array MUST be allocated in library
 *
 * @param bytes - byte array
 *)
procedure delete_byte_array(const bytes: PByte); cdecl; external DllName;

{$endregion}

{$region 'aes'}

(**
 * Decrypt data with aes-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 *)
procedure aes_cbc_decrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; const iv_bytes: PByte; var output_bytes: PByte; var ouput_size: Cardinal; const zeros_padding: Boolean = False); cdecl; external DllName;

(**
 * Encrypt data with aes-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 *)
procedure aes_cbc_encrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; const iv_bytes: PByte; var output_bytes: PByte; var ouput_size: Cardinal; const zeros_padding: Boolean = False); cdecl; external DllName;

(**
 * Decrypt data with aes-cfb
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 *)
procedure aes_cfb_decrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; const iv_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

(**
 * Encrypt data with aes-cfb
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 *)
procedure aes_cfb_encrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; const iv_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

(**
 * Decrypt data with aes-ecb
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 *)
procedure aes_ecb_decrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; var output_bytes: PByte; var ouput_size: Cardinal; const zeros_padding: Boolean = False); cdecl; external DllName;

(**
 * Encrypt data with aes-ecb
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 *)
procedure aes_ecb_encrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const key_size: Cardinal; var output_bytes: PByte; var ouput_size: Cardinal; const zeros_padding: Boolean = False); cdecl; external DllName;

{$endregion}

{$region 'big integer'}

(**
 * result = (value ^ exponent) % modulus
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_hex - value in hex format (e.g. "0x01020304...")
 * @param exponent_hex - exponent in hex format (e.g. "0x01020304...")
 * @param modulus_hex - modulus in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure big_integer_mod_pow(const value_hex: PAnsiChar; const exponent_hex: PAnsiChar; const modulus_hex: PAnsiChar; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

{$endregion}

{$region 'diffie-hellman'}

(**
 * Generate public and private keys
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param p_hex - 'p' value in hex format (e.g. "0x01020304...")
 * @param g_hex - 'g' value in hex format (e.g. "0x01020304...")
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 *)
procedure dh_key_pair(const p_hex: PAnsiChar; const g_hex: PAnsiChar; var private_key_bytes: PByte; var private_key_size: Cardinal; var public_key_bytes: PByte; var public_key_size: Cardinal); cdecl; external DllName;

(**
 * Generate shared key
 *
 * @note Caller MUST delete 'shared_key_bytes' with helper function 'delete_byte_array'
 *
 * @param p_hex - 'p' value in hex format (e.g. "0x01020304...")
 * @param g_hex - 'g' value in hex format (e.g. "0x01020304...")
 * @param private_key_bytes - private key byte array
 * @param other_public_key_bytes - other public key byte array
 * @param shared_key_bytes - pointer to null byte array to store shared key
 * @param shared_key_size - pointer to unsigned integer to store 'shared_key_bytes' size
 *)
procedure dh_shared_key(const p_hex: PAnsiChar; const g_hex: PAnsiChar; const private_key_bytes: PByte; const other_public_key_bytes: PByte; var shared_key_bytes: PByte; var shared_key_size: Cardinal); cdecl; external DllName;

{$endregion}

{$region 'hash'}

(**
 * md2 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 *)
procedure md2(const input_bytes: PByte; const input_size: Cardinal; var output_bytes: PByte); cdecl; external DllName;

(**
 * md4 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 *)
procedure md4(const input_bytes: PByte; const input_size: Cardinal; var output_bytes: PByte); cdecl; external DllName;

(**
 * md5 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 *)
procedure md5(const input_bytes: PByte; const input_size: Cardinal; var output_bytes: PByte); cdecl; external DllName;

(**
 * poly1305 (IETF's variant) hash of byte array of data
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param output_bytes - pointer to byte array with defined size to store hash
 *)
procedure poly1305_tls(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

{$endregion}

{$region 'pbkdf2'}

(**
 * Generate byte array for defined size
 *
 * @note Caller MUST allocate 'output_bytes' with size 'output_size'
 *
 * @param password_bytes - password byte array
 * @param password_size - size of 'password_bytes'
 * @param salt_bytes - salt byte array
 * @param salt_size - size of 'salt_bytes'
 * @param iterations_count - iterations count
 * @param output_bytes - pointer to byte array with defined size
 * @param output_size - size of 'output_bytes'
 *)
procedure pbkdf2_hmac_sha1(const password_bytes: PByte; const password_size: Cardinal; const salt_bytes: PByte; const salt_size: Cardinal; const iterations_count: Cardinal; var output_bytes: PByte; const output_size: Cardinal); cdecl; external DllName;

(**
 * Generate byte array for defined size
 *
 * @note Caller MUST allocate 'output_bytes' with size 'output_size'
 *
 * @param password_bytes - password byte array
 * @param password_size - size of 'password_bytes'
 * @param salt_bytes - salt byte array
 * @param salt_size - size of 'salt_bytes'
 * @param iterations_count - iterations count
 * @param output_bytes - pointer to byte array with defined size
 * @param output_size - size of 'output_bytes'
 *)
procedure pbkdf2_hmac_sha256(const password_bytes: PByte; const password_size: Cardinal; const salt_bytes: PByte; const salt_size: Cardinal; const iterations_count: Cardinal; var output_bytes: PByte; const output_size: Cardinal); cdecl; external DllName;

{$endregion}

{$region 'rsa'}

(**
 * Decrypt data with rsa pkcs1 padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa pkcs1 padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Export public key from private key
 *
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 *)
procedure rsa_export_public_key(const private_key_bytes: PByte; const private_key_size: Cardinal; var public_key_bytes: PByte; var public_key_size: Cardinal); cdecl; external DllName;

(**
 * Generate rsa key pair for defined size
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param key_size - size of the key in bits
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 * @param exponent - define key exponent value, default value = 65537
 *)
procedure rsa_key_pair(const key_size: Cardinal; var private_key_bytes: PByte; var private_key_size: Cardinal; var public_key_bytes: PByte; var public_key_size: Cardinal; const exponent: Cardinal = 65537); cdecl; external DllName;

(**
 * Decrypt data with rsa no padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_no_padding_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa no padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_no_padding_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md2_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md2_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep md4
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md4_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep md4
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md4_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md5_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_md5_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha1_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha1_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha224_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha224_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha256_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha256_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha384_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha384_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Decrypt data with rsa oaep sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha512_decrypt(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Encrypt data with rsa oaep sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_oaep_sha512_encrypt(const input_bytes: PByte; const input_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_md2_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss md2
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_md2_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_md5_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss md5
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_md5_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_sha1_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss sha1
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_sha1_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_sha224_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss sha224
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_sha224_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_sha256_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss sha256
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_sha256_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_sha384_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss sha384
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_sha384_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

(**
 * Generate signature of data with rsa pss sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 *)
procedure rsa_pss_sha512_sign(const input_bytes: PByte; const input_size: Cardinal; const private_key_bytes: PByte; const private_key_size: Cardinal; var output_bytes: PByte; var output_size: Cardinal); cdecl; external DllName;

(**
 * Verify signature of data with rsa pss sha512
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 *)
procedure rsa_pss_sha512_verify(const input_bytes: PByte; const input_size: Cardinal; const signature_bytes: PByte; const signature_size: Cardinal; const public_key_bytes: PByte; const public_key_size: Cardinal; var result: Boolean); cdecl; external DllName;

{$endregion}

{$region 'xsalsa20'}

(**
 * Decrypt data with xsalsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 *)
procedure xsalsa20_decrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const iv_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

(**
 * Encrypt data with xsalsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 *)
procedure xsalsa20_encrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const iv_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

(**
 * Decrypt data with xsalsa20 and verify poly1305 (IETF's variant) hash
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size - 16'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 * @param verify - define verification for poly1305 hash, default value = true
 *)
procedure xsalsa20_poly1305_tls_decrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const iv_bytes: PByte; var output_bytes: PByte; const verify: Boolean = True); cdecl; external DllName;

(**
 * Encrypt data with xsalsa20 and calculate poly1305 (IETF's variant) hash
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size + 16'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 *)
procedure xsalsa20_poly1305_tls_encrypt(const input_bytes: PByte; const input_size: Cardinal; const key_bytes: PByte; const iv_bytes: PByte; var output_bytes: PByte); cdecl; external DllName;

{$endregion}

implementation

end.
