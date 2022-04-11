unit CryptoPP;

interface

uses
  System.SysUtils, CryptoPP_Lib;

type
  TKeyPair = record
  public
    PrivateKey: TArray<Byte>;
    PublicKey: TArray<Byte>;
  end;

  TAES = record
  public
    function Cbc_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
    function Cbc_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
    function Cfb_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Cfb_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Ecb_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
    function Ecb_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
    function Gcm_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Gcm_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
  end;

  TBigInteger = record
  public
    function ModPow(const ValueHex: string; const ExponentHex: string; const ModulusHex: string): TArray<Byte>;
  end;

  TChaCha20 = record
  public
    function Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
  end;

  TDiffieHellman = record
  public
    function KeyPair(const PHex: string; const GHex: string): TKeyPair;
    function SharedKey(const PHex: string; const GHex: string; const PrivateKey: TArray<Byte>; const OtherPublicKey: TArray<Byte>): TArray<Byte>;
  end;

  TECDSA = record
  public
    function ExportPublicKey(const PrivateKey: TArray<Byte>): TArray<Byte>;
    function KeyPair(const EllipticCurve: Byte = 0): TKeyPair;
    function Sign(const HashMethod: string; const Data: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
    function Verify(const HashMethod: string; const Data: TArray<Byte>; const Signature: TArray<Byte>; const PublicKey: TArray<Byte>): Boolean;
  end;

  THash = record
  public
    function MD2(const Data: TArray<Byte>): TArray<Byte>;
    function MD4(const Data: TArray<Byte>): TArray<Byte>;
    function MD5(const Data: TArray<Byte>): TArray<Byte>;
    function Poly1305_Tls(const Data: TArray<Byte>; const Key: TArray<Byte>): TArray<Byte>;
  end;

  TPBKDF2 = record
  public
    function HmacSha1(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
    function HmacSha256(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
    function HmacSha512(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
  end;

  TRSA = record
  public
    function Decrypt(const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
    function Encrypt(const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
    function ExportPublicKey(const PrivateKey: TArray<Byte>): TArray<Byte>;
    function KeyPair(const KeySize: Cardinal; const Exponent: Cardinal = 65537): TKeyPair;
    function NoPadding_Decrypt(const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
    function NoPadding_Encrypt(const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
    function Oaep_Decrypt(const HashMethod: string; const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
    function Oaep_Encrypt(const HashMethod: string; const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
    function Pss_Sign(const HashMethod: string; const Data: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
    function Pss_Verify(const HashMethod: string; const Data: TArray<Byte>; const Signature: TArray<Byte>; const PublicKey: TArray<Byte>): Boolean;
  end;

  TSalsa20 = record
  public
    function Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
  end;

  TXSalsa20 = record
  public
    function Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
    function Poly1305_Tls_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const Verify: Boolean = True): TArray<Byte>;
    function Poly1305_Tls_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
  end;

  TCrypto = record
  public
    AES: TAES;
    BigInteger: TBigInteger;
    ChaCha20: TChaCha20;
    DiffieHellman: TDiffieHellman;
    ECDSA: TECDSA;
    Hash: THash;
    PBKDF2: TPBKDF2;
    RSA: TRSA;
    Salsa20: TSalsa20;
    XSalsa20: TXSalsa20;
  end;

var
  Crypto: TCrypto;

implementation

{---------- TAES ----------}

function TAES.Cbc_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_cbc_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), @IV[0], OutputPointer, OutputSize, ZerosPadding);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TAES.Cbc_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_cbc_encrypt(@Data[0], Length(Data), @Key[0], Length(Key), @IV[0], OutputPointer, OutputSize, ZerosPadding);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TAES.Cfb_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(CipherData));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.aes_cfb_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TAES.Cfb_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(Data));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.aes_cfb_encrypt(@Data[0], Length(Data), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TAES.Ecb_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_ecb_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), OutputPointer, OutputSize, ZerosPadding);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TAES.Ecb_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const ZerosPadding: Boolean = False): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_ecb_encrypt(@Data[0], Length(Data), @Key[0], Length(Key), OutputPointer, OutputSize, ZerosPadding);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TAES.Gcm_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_gcm_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), @IV[0], Length(IV), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TAES.Gcm_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.aes_gcm_encrypt(@Data[0], Length(Data), @Key[0], Length(Key), @IV[0], Length(IV), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

{---------- TBigInteger ----------}

function TBigInteger.ModPow(const ValueHex: string; const ExponentHex: string; const ModulusHex: string): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.big_integer_mod_pow(PAnsiChar(AnsiString(ValueHex)), PAnsiChar(AnsiString(ExponentHex)), PAnsiChar(AnsiString(ModulusHex)), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

{---------- TChaCha20 ----------}

function TChaCha20.Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(CipherData));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.chacha20_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TChaCha20.Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(Data));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.chacha20_decrypt(@Data[0], Length(Data), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

{---------- TDiffieHellman ----------}

function TDiffieHellman.KeyPair(const PHex: string; const GHex: string): TKeyPair;
var
  PrivateKeyPointer: PByte;
  PrivateKeySize: Cardinal;
  PublicKeyPointer: PByte;
  PublicKeySize: Cardinal;
  KeyPair: TKeyPair;
begin
  cryptopp_lib.dh_key_pair(PAnsiChar(AnsiString('0x' + PHex)), PAnsiChar(AnsiString('0x' + GHex)), PrivateKeyPointer, PrivateKeySize, PublicKeyPointer, PublicKeySize);

  SetLength(KeyPair.PrivateKey, PrivateKeySize);
  SetLength(KeyPair.PublicKey, PublicKeySize);
  Move(PrivateKeyPointer^, KeyPair.PrivateKey[0], PrivateKeySize);
  Move(PublicKeyPointer^, KeyPair.PublicKey[0], PublicKeySize);

  cryptopp_lib.delete_byte_array(PrivateKeyPointer);
  cryptopp_lib.delete_byte_array(PublicKeyPointer);

  Result := KeyPair;
end;

function TDiffieHellman.SharedKey(const PHex: string; const GHex: string; const PrivateKey: TArray<Byte>; const OtherPublicKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.dh_shared_key(PAnsiChar(AnsiString('0x' + PHex)), PAnsiChar(AnsiString('0x' + GHex)), @PrivateKey[0], @OtherPublicKey[0], OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

{---------- TECDSA ----------}

function TECDSA.ExportPublicKey(const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.ecdsa_export_public_key(@PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TECDSA.KeyPair(const EllipticCurve: Byte = 0): TKeyPair;
var
  PrivateKeyPointer: PByte;
  PrivateKeySize: Cardinal;
  PublicKeyPointer: PByte;
  PublicKeySize: Cardinal;
  KeyPair: TKeyPair;
begin
  cryptopp_lib.ecdsa_key_pair(EllipticCurve, PrivateKeyPointer, PrivateKeySize, PublicKeyPointer, PublicKeySize);

  SetLength(KeyPair.PrivateKey, PrivateKeySize);
  SetLength(KeyPair.PublicKey, PublicKeySize);
  Move(PrivateKeyPointer^, KeyPair.PrivateKey[0], PrivateKeySize);
  Move(PublicKeyPointer^, KeyPair.PublicKey[0], PublicKeySize);

  cryptopp_lib.delete_byte_array(PrivateKeyPointer);
  cryptopp_lib.delete_byte_array(PublicKeyPointer);

  Result := KeyPair;
end;

function TECDSA.Sign(const HashMethod: string; const Data: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  Head, ResultBytes: TArray<Byte>;
begin
  OutputPointer := nil;
  ResultBytes := [];

  if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.ecdsa_sha1_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.ecdsa_sha256_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  if Assigned(OutputPointer) then
  begin
    SetLength(ResultBytes, OutputSize);
    Move(OutputPointer^, ResultBytes[0], OutputSize);

    cryptopp_lib.delete_byte_array(OutputPointer);
  end;

  if ResultBytes[32] > 127 then
    Head := [2, 33, 00]
  else
    Head := [2, 32];

  Insert(Head, ResultBytes, 32);

  if ResultBytes[0] > 127 then
    Head := [2, 33, 00]
  else
    Head := [2, 32];

  ResultBytes := Head + ResultBytes;
  Result := [48, Length(ResultBytes)] + ResultBytes;
end;

function TECDSA.Verify(const HashMethod: string; const Data: TArray<Byte>; const Signature: TArray<Byte>; const PublicKey: TArray<Byte>): Boolean;
var
  ResultBoolean: Boolean;
  R, S, SignatureFormatted: TArray<Byte>;
begin
  ResultBoolean := False;
  R := Copy(Signature, 4, Signature[3]);
  S := Copy(Signature, Signature[3] + 6, Signature[Signature[3] + 1]);

  if Length(R) <> 32 then
    R := Copy(R, 1, 32);

  if Length(S) <> 32 then
    S := Copy(S, 1, 32);

  SignatureFormatted := R + S;

  if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.ecdsa_sha1_verify(@Data[0], Length(Data), @SignatureFormatted[0], Length(SignatureFormatted), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.ecdsa_sha256_verify(@Data[0], Length(Data), @SignatureFormatted[0], Length(SignatureFormatted), @PublicKey[0], Length(PublicKey), ResultBoolean);

  Result := ResultBoolean;
end;

{---------- THash ----------}

function THash.MD2(const Data: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.md2(@Data[0], Length(Data), OutputPointer);

  Result := ResultBytes;
end;

function THash.MD4(const Data: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.md4(@Data[0], Length(Data), OutputPointer);

  Result := ResultBytes;
end;

function THash.MD5(const Data: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.md5(@Data[0], Length(Data), OutputPointer);

  Result := ResultBytes;
end;

function THash.Poly1305_Tls(const Data: TArray<Byte>; const Key: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.poly1305_tls(@Data[0], Length(Data), @Key[0], OutputPointer);

  Result := ResultBytes;
end;

{---------- TPBKDF2 ----------}

function TPBKDF2.HmacSha1(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, ResultSize);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.pbkdf2_hmac_sha1(@Password[0], Length(Password), @Salt[0], Length(Salt), IterationsCount, OutputPointer, ResultSize);

  Result := ResultBytes;
end;

function TPBKDF2.HmacSha256(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, ResultSize);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.pbkdf2_hmac_sha256(@Password[0], Length(Password), @Salt[0], Length(Salt), IterationsCount, OutputPointer, ResultSize);

  Result := ResultBytes;
end;

function TPBKDF2.HmacSha512(const Password: TArray<Byte>; const Salt: TArray<Byte>; const IterationsCount: Cardinal; const ResultSize: Cardinal = 32): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, ResultSize);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.pbkdf2_hmac_sha512(@Password[0], Length(Password), @Salt[0], Length(Salt), IterationsCount, OutputPointer, ResultSize);

  Result := ResultBytes;
end;

{---------- TRSA ----------}

function TRSA.Decrypt(const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.rsa_ecb_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TRSA.Encrypt(const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.rsa_ecb_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TRSA.ExportPublicKey(const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.rsa_export_public_key(@PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TRSA.KeyPair(const KeySize: Cardinal; const Exponent: Cardinal = 65537): TKeyPair;
var
  PrivateKeyPointer: PByte;
  PrivateKeySize: Cardinal;
  PublicKeyPointer: PByte;
  PublicKeySize: Cardinal;
  KeyPair: TKeyPair;
begin
  cryptopp_lib.rsa_key_pair(KeySize, PrivateKeyPointer, PrivateKeySize, PublicKeyPointer, PublicKeySize, Exponent);

  SetLength(KeyPair.PrivateKey, PrivateKeySize);
  SetLength(KeyPair.PublicKey, PublicKeySize);
  Move(PrivateKeyPointer^, KeyPair.PrivateKey[0], PrivateKeySize);
  Move(PublicKeyPointer^, KeyPair.PublicKey[0], PublicKeySize);

  cryptopp_lib.delete_byte_array(PrivateKeyPointer);
  cryptopp_lib.delete_byte_array(PublicKeyPointer);

  Result := KeyPair;
end;

function TRSA.NoPadding_Decrypt(const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.rsa_no_padding_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TRSA.NoPadding_Encrypt(const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  cryptopp_lib.rsa_no_padding_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize);

  SetLength(ResultBytes, OutputSize);
  Move(OutputPointer^, ResultBytes[0], OutputSize);

  cryptopp_lib.delete_byte_array(OutputPointer);

  Result := ResultBytes;
end;

function TRSA.Oaep_Decrypt(const HashMethod: string; const CipherData: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  OutputPointer := nil;
  ResultBytes := [];

  if HashMethod.ToLower().Equals('md2') then
    cryptopp_lib.rsa_oaep_md2_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('md4') then
    cryptopp_lib.rsa_oaep_md4_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('md5') then
    cryptopp_lib.rsa_oaep_md5_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.rsa_oaep_sha1_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha224') then
    cryptopp_lib.rsa_oaep_sha224_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.rsa_oaep_sha256_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha384') then
    cryptopp_lib.rsa_oaep_sha384_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha512') then
    cryptopp_lib.rsa_oaep_sha512_decrypt(@CipherData[0], Length(CipherData), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  if Assigned(OutputPointer) then
  begin
    SetLength(ResultBytes, OutputSize);
    Move(OutputPointer^, ResultBytes[0], OutputSize);

    cryptopp_lib.delete_byte_array(OutputPointer);
  end;

  Result := ResultBytes;
end;

function TRSA.Oaep_Encrypt(const HashMethod: string; const Data: TArray<Byte>; const PublicKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  OutputPointer := nil;
  ResultBytes := [];

  if HashMethod.ToLower().Equals('md2') then
    cryptopp_lib.rsa_oaep_md2_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('md4') then
    cryptopp_lib.rsa_oaep_md4_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('md5') then
    cryptopp_lib.rsa_oaep_md5_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.rsa_oaep_sha1_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha224') then
    cryptopp_lib.rsa_oaep_sha224_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.rsa_oaep_sha256_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha384') then
    cryptopp_lib.rsa_oaep_sha384_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha512') then
    cryptopp_lib.rsa_oaep_sha512_encrypt(@Data[0], Length(Data), @PublicKey[0], Length(PublicKey), OutputPointer, OutputSize);

  if Assigned(OutputPointer) then
  begin
    SetLength(ResultBytes, OutputSize);
    Move(OutputPointer^, ResultBytes[0], OutputSize);

    cryptopp_lib.delete_byte_array(OutputPointer);
  end;

  Result := ResultBytes;
end;

function TRSA.Pss_Sign(const HashMethod: string; const Data: TArray<Byte>; const PrivateKey: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  OutputSize: Cardinal;
  ResultBytes: TArray<Byte>;
begin
  OutputPointer := nil;
  ResultBytes := [];

  if HashMethod.ToLower().Equals('md2') then
    cryptopp_lib.rsa_pss_md2_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('md5') then
    cryptopp_lib.rsa_pss_md5_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.rsa_pss_sha1_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha224') then
    cryptopp_lib.rsa_pss_sha224_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.rsa_pss_sha256_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha384') then
    cryptopp_lib.rsa_pss_sha384_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize)
  else if HashMethod.ToLower().Equals('sha512') then
    cryptopp_lib.rsa_pss_sha512_sign(@Data[0], Length(Data), @PrivateKey[0], Length(PrivateKey), OutputPointer, OutputSize);

  if Assigned(OutputPointer) then
  begin
    SetLength(ResultBytes, OutputSize);
    Move(OutputPointer^, ResultBytes[0], OutputSize);

    cryptopp_lib.delete_byte_array(OutputPointer);
  end;

  Result := ResultBytes;
end;

function TRSA.Pss_Verify(const HashMethod: string; const Data: TArray<Byte>; const Signature: TArray<Byte>; const PublicKey: TArray<Byte>): Boolean;
var
  ResultBoolean: Boolean;
begin
  ResultBoolean := False;

  if HashMethod.ToLower().Equals('md2') then
    cryptopp_lib.rsa_pss_md2_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('md5') then
    cryptopp_lib.rsa_pss_md5_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha1') then
    cryptopp_lib.rsa_pss_sha1_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha224') then
    cryptopp_lib.rsa_pss_sha224_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha256') then
    cryptopp_lib.rsa_pss_sha256_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha384') then
    cryptopp_lib.rsa_pss_sha384_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean)
  else if HashMethod.ToLower().Equals('sha512') then
    cryptopp_lib.rsa_pss_sha512_verify(@Data[0], Length(Data), @Signature[0], Length(Signature), @PublicKey[0], Length(PublicKey), ResultBoolean);

  Result := ResultBoolean;
end;

{---------- TSalsa20 ----------}

function TSalsa20.Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(CipherData));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.salsa20_decrypt(@CipherData[0], Length(CipherData), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TSalsa20.Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(Data));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.salsa20_decrypt(@Data[0], Length(Data), @Key[0], Length(Key), @IV[0], OutputPointer);

  Result := ResultBytes;
end;

{---------- TXSalsa20 ----------}

function TXSalsa20.Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(CipherData));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.xsalsa20_decrypt(@CipherData[0], Length(CipherData), @Key[0], @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TXSalsa20.Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(Data));

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.xsalsa20_decrypt(@Data[0], Length(Data), @Key[0], @IV[0], OutputPointer);

  Result := ResultBytes;
end;

function TXSalsa20.Poly1305_Tls_Decrypt(const CipherData: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>; const Verify: Boolean = True): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(CipherData) - 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.xsalsa20_poly1305_tls_decrypt(@CipherData[0], Length(CipherData), @Key[0], @IV[0], OutputPointer, Verify);

  Result := ResultBytes;
end;

function TXSalsa20.Poly1305_Tls_Encrypt(const Data: TArray<Byte>; const Key: TArray<Byte>; const IV: TArray<Byte>): TArray<Byte>;
var
  OutputPointer: PByte;
  ResultBytes: TArray<Byte>;
begin
  SetLength(ResultBytes, Length(Data) + 16);

  OutputPointer := @ResultBytes[0];

  cryptopp_lib.xsalsa20_poly1305_tls_encrypt(@Data[0], Length(Data), @Key[0], @IV[0], OutputPointer);

  Result := ResultBytes;
end;

end.
