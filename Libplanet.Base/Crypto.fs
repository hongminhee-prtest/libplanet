namespace Libplanet.Base.Crypto

open System
open System.Diagnostics.Contracts
open System.IO
open Org.BouncyCastle.Asn1
open Org.BouncyCastle.Asn1.Sec
open Org.BouncyCastle.Asn1.X9
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Modes
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Math
open Org.BouncyCastle.Math.EC
open Org.BouncyCastle.Security

module internal Commons =

    [<Pure>]
    let GetECParameters(name : string) : ECDomainParameters =
        let ps : X9ECParameters = SecNamedCurves.GetByName name
        ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H)

    [<Pure>]
    let GetSecp256k1() : ECDomainParameters =
        GetECParameters "secp256k1"

    [<Literal>]
    let KeyBits : int = 256

    [<Literal>]
    let MacBits : int = 128

    [<Literal>]
    let NonceBits : int = 128

type Aesgcm =

    val private key : byte[]
    val private secureRandom : SecureRandom

    new(key : byte[]) =
        {
            key =
                if key.Length <> Commons.KeyBits / 8
                then
                    invalidArg "key" <|
                        String.Format(
                            "Key needs to be {0} bits",
                            Commons.KeyBits
                        )
                else
                    key
            secureRandom = SecureRandom()
        }

    member this.Encrypt(message : byte[], nonSecret : byte[]) : byte[]=
        let nonce : byte[] = Array.zeroCreate <| Commons.NonceBits / 8
        this.secureRandom.NextBytes(nonce, 0, nonce.Length)

        let cipher = GcmBlockCipher <| AesEngine()
        let parameters = this.GetAeadParameters(nonce, nonSecret)
        cipher.Init(true, parameters)

        let ciphertext : byte[] =
                Array.zeroCreate <| cipher.GetOutputSize message.Length
        let len = cipher.ProcessBytes(message, 0, message.Length, ciphertext, 0)
        cipher.DoFinal(ciphertext, len) |> ignore

        Array.concat [nonSecret; nonce; ciphertext]

    member this.Encrypt(message : byte[]) : byte[] =
        this.Encrypt(message, array.Empty())

    [<Pure>]
    member this.Decrypt(ciphertext : byte[], nonSecretLength : int) : byte[] =
        if isNull ciphertext then nullArg("ciphertext")
        if Array.isEmpty ciphertext
        then invalidArg "ciphertext" "the input data cannot be empty"

        let nonSecret : byte[] = Array.sub ciphertext 0 nonSecretLength
        let nonceLength : int = Commons.NonceBits / 8
        let nonce : byte[] = Array.sub ciphertext nonSecretLength nonceLength

        let cipher = GcmBlockCipher <| AesEngine()
        let parameters = this.GetAeadParameters(nonce, nonSecret)
        cipher.Init(false, parameters)

        let cipherOffset : int = nonSecretLength + nonceLength
        let cipherBytesLength : int = ciphertext.Length - cipherOffset
        let message : byte[] =
                Array.zeroCreate <| cipher.GetOutputSize(cipherBytesLength)

        let len = cipher.ProcessBytes(
                    ciphertext, cipherOffset, cipherBytesLength, message, 0)
        cipher.DoFinal(message, len) |> ignore
        message

    [<Pure>]
    member this.Decrypt(ciphertext : byte[]) : byte[] =
        this.Decrypt(ciphertext, 0)

    [<Pure>]
    member this.GetAeadParameters
            (nonce : byte[], nonSecret : byte[]) : AeadParameters =
            AeadParameters(
                KeyParameter this.key,
                Commons.MacBits,
                nonce,
                nonSecret
            )

type PrivateKey =

    val keyParam : ECPrivateKeyParameters

    new(byteArray : byte[]) =
        { keyParam =
            ECPrivateKeyParameters(
                "ECDSA",
                BigInteger(1, byteArray),
                Commons.GetSecp256k1()
            )
        }

    new() =
        let gen = ECKeyPairGenerator()
        let secureRandom = SecureRandom()
        let ecParams : ECDomainParameters = Commons.GetSecp256k1()
        let keyGenParam = ECKeyGenerationParameters(ecParams, secureRandom)
        gen.Init keyGenParam
        { keyParam = gen.GenerateKeyPair().Private :?> ECPrivateKeyParameters }

    [<Pure>]
    member this.ByteArray : byte[] = this.keyParam.D.ToByteArrayUnsigned()

    [<Pure>]
    member this.PublicKey : PublicKey =
        let ecParams : ECDomainParameters = Commons.GetSecp256k1()
        let q : ECPoint = ecParams.G.Multiply this.keyParam.D
        let kp = ECPublicKeyParameters("ECDSA", q, ecParams)
        PublicKey kp

    [<Pure>]
    member this.Sign(ciphertext : byte[]) : byte[] =
        let h = Sha256Digest()
        let hashed : byte[] = Array.zeroCreate <| h.GetDigestSize()
        h.BlockUpdate(ciphertext ,0, ciphertext.Length)
        h.DoFinal(hashed, 0) |> ignore
        h.Reset() |> ignore

        let kCalculator = HMacDsaKCalculator h
        let signer = ECDsaSigner kCalculator
        signer.Init(true, this.keyParam)
        let rs : BigInteger[] = signer.GenerateSignature hashed
        let r = rs.[0]
        let otherS : BigInteger = this.keyParam.Parameters.N.Subtract rs.[1]
        let s = match rs.[1].CompareTo otherS with
                | 1 -> otherS
                | _ -> rs.[1]

        use bos = new MemoryStream(72)
        let seq = DerSequenceGenerator bos
        seq.AddObject <| DerInteger r
        seq.AddObject <| DerInteger s
        seq.Close()
        bos.ToArray()

    [<Pure>]
    member this.Decrypt(ciphertext : byte[]) : byte[] =
        let pubKey = PublicKey(Array.sub ciphertext 0 33)
        let aesKey : byte[] = this.ExchangeKey pubKey
        let aes = Aesgcm aesKey
        aes.Decrypt(ciphertext, 33)

    [<Pure>]
    member this.ExchangeKey(publicKey : PublicKey) : byte[] =
        let p : ECPoint = this.CalculatePoint publicKey.keyParam
        let x : BigInteger = p.AffineXCoord.ToBigInteger()
        let y : BigInteger = p.AffineYCoord.ToBigInteger()
        let xbuf : byte[] = x.ToByteArrayUnsigned()
        let ybuf : byte[] = [|byte <| if y.TestBit(0) then 0x03 else 0x02|]
        let hash : Sha256Digest = Sha256Digest()
        let result : byte[] = Array.zeroCreate <| hash.GetDigestSize()
        hash.BlockUpdate(ybuf, 0, ybuf.Length)
        hash.BlockUpdate(xbuf, 0, xbuf.Length)
        hash.DoFinal(result, 0) |> ignore
        result

    [<Pure>]
    member private this.CalculatePoint
        (pubKeyParams : ECPublicKeyParameters) : ECPoint =

        let dp : ECDomainParameters = this.keyParam.Parameters
        if not (dp.Equals this.keyParam.Parameters)
        then
            invalidOp "ECDH public key has wrong domain parameters"

        let mutable d : BigInteger = this.keyParam.D
        let mutable q : ECPoint =
            dp.Curve.DecodePoint <| pubKeyParams.Q.GetEncoded true
        if q.IsInfinity
        then
            invalidOp "Infinity is not a valid public key for ECDH"

        let h = dp.H
        if not <| h.Equals BigInteger.One
        then
            d <- dp.H.ModInverse(dp.N).Multiply(d).Mod(dp.N)
            q <- ECAlgorithms.ReferenceMultiply(q, h)

        let p : ECPoint = q.Multiply(d).Normalize()
        if p.IsInfinity
        then
            invalidOp "Infinity is not a valid agreement value for ECDH"
        p

    interface IEquatable<PrivateKey> with
        member this.Equals(other : PrivateKey) : bool =
            this.keyParam.Equals(other.keyParam)

    override this.Equals(other : obj) : bool =
        if other :? PrivateKey
        then
            (this :> IEquatable<PrivateKey>).Equals(other :?> PrivateKey)
        else
            false

    override this.GetHashCode() : int =
        this.keyParam.GetHashCode()

    static member op_Equality(a, b : PrivateKey) : bool =
        (a :> IEquatable<PrivateKey>).Equals(b)

    static member op_Inequality(a, b : PrivateKey) : bool =
        not (a = b)

and PublicKey =

    val internal keyParam : ECPublicKeyParameters

    new(byteArray : byte[]) =
        PublicKey(
            let ecParams = Commons.GetSecp256k1()
            ECPublicKeyParameters(
                "ECDSA",
                ecParams.Curve.DecodePoint byteArray,
                ecParams
            )
        )

    internal new(keyParam : ECPublicKeyParameters) =
        { keyParam = keyParam }

    [<Pure>]
    member this.Verify(message : byte[],
                       signature : byte[],
                       algorithm : string) : bool =
        let verifier : ISigner = SignerUtilities.GetSigner algorithm
        verifier.Init(false, this.keyParam)
        verifier.BlockUpdate(message, 0, message.Length)
        verifier.VerifySignature signature

    [<Pure>]
    member this.Verify(message : byte[], signature : byte[]) : bool =
        this.Verify(message, signature, "SHA256withECDSA")

    member this.Encrypt(message : byte[]) : byte[] =
        let disposablePrivKey = PrivateKey()
        let aesKey : byte[] = disposablePrivKey.ExchangeKey this
        let aes = Aesgcm aesKey
        aes.Encrypt(message, disposablePrivKey.PublicKey.Format true)

    [<Pure>]
    member this.Format(compress : bool) =
        this.keyParam.Q.GetEncoded compress

    interface IEquatable<PublicKey> with
        member this.Equals(other : PublicKey) : bool =
            this.keyParam.Equals(other.keyParam)

    override this.Equals(other : obj) : bool =
        if other :? PublicKey
        then
            (this :> IEquatable<PublicKey>).Equals(other :?> PublicKey)
        else
            false

    override this.GetHashCode() : int =
        this.keyParam.GetHashCode()

    static member op_Equality(a, b : PublicKey) : bool =
        (a :> IEquatable<PublicKey>).Equals(b)

    static member op_Inequality(a, b : PublicKey) : bool =
        not (a = b)
