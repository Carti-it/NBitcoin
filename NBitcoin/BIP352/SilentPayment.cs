#if HAS_SPAN
#nullable enable
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NBitcoin.BIP352;

/// <seealso href="https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py"/>
public static class SilentPayment
{
	private static readonly byte[] NUMS = Encoders.Hex.DecodeData("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

	public static PubKey ComputeSharedSecretReceiver(OutPoint[] prevOuts, PubKey[] pubKeys, Key b) =>
		ComputeSharedSecret(prevOuts, A: SumPublicKeys(pubKeys), b);

	public static Dictionary<SilentPaymentAddress, TaprootPubKey[]> GetPubKeys(IEnumerable<SilentPaymentAddress> recipients, Utxo[] utxos) =>
		recipients
			.GroupBy(x => x.ScanKey, (scanKey, addresses) =>
			{
				var sharedSecret = ComputeSharedSecretSender(utxos, scanKey);
				return addresses.Select((addr, k) => (
					Address: addr,
					PubKey: ComputePubKey(addr.SpendKey, sharedSecret, (uint) k)));
			})
			.SelectMany(x => x)
			.GroupBy(x => x.Address)
			.ToDictionary(
				x => x.Key,
				x => x.Select(y => y.PubKey).ToArray());

	public static (SilentPaymentAddress Address, TaprootPubKey PubKey)[] GetPubKeys(IEnumerable<SilentPaymentAddress> addresses, PubKey sharedSecret, PubKey[] outputs) =>
		throw new NotImplementedException();
		/*Enumerable
			.Range(0, outputs.Length)
			.Select(n => addresses.Select(address =>
				(Address: address, PubKey: ComputePubKey(address.SpendKey, sharedSecret, (uint) n))))
			.SelectMany(x => x)
			.Where(x => outputs.Select(o => o.ECKey.Q).Contains(x.PubKey.ECKey.Q))
			.ToArray();*/

	public static Key CreateLabel(Key scanKey, uint label) =>
		new (TaggedHash("BIP0352/Label", scanKey.ToBytes().Concat(Serialize32(label)).ToArray()));

	// Let ecdh_shared_secret = input_hash·a·Bscan
	private static PubKey ComputeSharedSecret(OutPoint[] outpoints, Key a, PubKey B) =>
		DHSharedSecret(InputHash(outpoints, a.PubKey), B, a);

	// Let ecdh_shared_secret = input_hash·bscan·A
	private static PubKey ComputeSharedSecret(OutPoint[] outpoints, PubKey A, Key b) =>
		DHSharedSecret(InputHash(outpoints, A), A, b);

	private static PubKey DHSharedSecret(Scalar inputHash, PubKey pubKey, Key privKey) =>
		TweakData(inputHash, pubKey).GetSharedPubkey(privKey);

	private static PubKey TweakData(Scalar inputHash, PubKey pubKey)
	{
		GE point = (inputHash * pubKey.ECKey.Q).ToGroupElement();
		ECPubKey ecPubKey = new ECPubKey(point, context: null);   // keeps full point, parity included
		return new PubKey(ecPubKey.ToBytes(compressed: true)); // 33-byte compressed encoding
	}

	// let tk = hash_BIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
	public static Key TweakKey(PubKey sharedSecret, uint k) =>
		new(TaggedHash( "BIP0352/SharedSecret", sharedSecret.ToBytes().Concat(Serialize32(k)).ToArray()));

	public static PubKey ComputeSharedSecretSender(Utxo[] utxos, PubKey B)
	{
		using var a = SumPrivateKeys(utxos);
		return ComputeSharedSecret(utxos.Select(x => x.OutPoint).ToArray(), a, B);
	}

	// Let input_hash = hashBIP0352/Inputs(outpointL || A)
	private static Scalar InputHash(OutPoint[] outpoints, PubKey A)
	{
		var outpointL = outpoints.Select(x => x.ToBytes()).OrderBy(x => x, BytesComparer.Instance).First();
		var hash = TaggedHash("BIP0352/Inputs", outpointL.Concat(A.ToBytes()).ToArray());
		return new Scalar(hash);
	}

	public static Key ComputePrivKey(Key spendKey, Key tweakKey) =>
		new((tweakKey._ECKey.sec + spendKey._ECKey.sec).ToBytes());

	public static PubKey? ExtractPubKey(Script scriptSig, WitScript txInWitness, Script prevOutScriptPubKey)
	{
		var spk = prevOutScriptPubKey;
		if (txInWitness != WitScript.Empty && spk.IsScriptType(ScriptType.Taproot))
		{
			var pubKeyParameters = PayToTaprootTemplate.Instance.ExtractScriptPubKeyParameters(spk);
			var annex = txInWitness[txInWitness.PushCount - 1][^1] == 0x50 ? 1 : 0;
			if (txInWitness.PushCount > annex &&
			    BytesComparer.Instance.Compare(txInWitness[txInWitness.PushCount - annex - 1][1..33], NUMS) == 0)
			{
				return null;
			}

			return new PubKey(pubKeyParameters.ToBytes());
		}

		if (txInWitness != WitScript.Empty && spk.IsScriptType(ScriptType.P2WPKH))
		{
			var witScriptParameters =
				PayToWitPubKeyHashTemplate.Instance.ExtractWitScriptParameters(txInWitness);
			if (witScriptParameters is { } nonNullWitScriptParameters &&
			    nonNullWitScriptParameters.PublicKey.IsCompressed)
			{
				var q = nonNullWitScriptParameters.PublicKey;
				return q.ToBytes()[0] == 0x02 ? q : new PubKey(new ECXOnlyPubKey(q.ECKey.Q.Negate(), null).ToBytes());
			}
		}

		if (scriptSig != Script.Empty && spk.IsScriptType(ScriptType.P2PKH))
		{
			var pubKeyId = PayToPubkeyHashTemplate.Instance.ExtractScriptPubKeyParameters(spk);
			var pubKeyHash = new uint160(pubKeyId.ToBytes());

			var scriptSigBytes = scriptSig.ToBytes();
			var pubKeyBytes = Enumerable.Range(33, scriptSigBytes.Length - 32)
				.Reverse()
				.Select(i => scriptSigBytes[(i - 33)..i])
				.Where(pkb => pkb[0] is 2 or 3 or 4)
				.FirstOrDefault(pkb => Hashes.Hash160(pkb) == pubKeyHash);

			return pubKeyBytes != null
				? new PubKey(pubKeyBytes)
				: null;
		}

		if (scriptSig != Script.Empty && spk.IsScriptType(ScriptType.P2SH))
		{
			var p2sh = PayToScriptHashTemplate.Instance.ExtractScriptSigParameters(scriptSig);
			if (txInWitness != WitScript.Empty && p2sh is not null &&
			    p2sh.RedeemScript.IsScriptType(ScriptType.P2WPKH))
			{
				var witScriptParameters =
					PayToWitPubKeyHashTemplate.Instance.ExtractWitScriptParameters(txInWitness);
				if (witScriptParameters is {PublicKey.IsCompressed: true})
				{
					var q = witScriptParameters.PublicKey;
					return q.ToBytes()[0] == 0x02 ? q : new PubKey(q.ECKey.Negate().ToXOnlyPubKey().ToBytes());
				}
			}
		}

		return null;
	}

	/// <param name="Bm">If no label is applied then B_m = B_spend.</param>
	/// <seealso href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding"/>
	/// <seealso href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#creating-outputs">
	/// Step 7. 
	/// </seealso>
	internal static TaprootPubKey ComputePubKey(PubKey Bm, PubKey sharedSecret, uint k)
	{
		// "Let t_k = hash_{BIP0352/SharedSecret}(ser_P(ecdh_shared_secret) || ser_32(k))"
		using var tk = TweakKey(sharedSecret, k);

		// "Let P_mn = t_k·G + Bm"
		var pmn = tk.PubKey.ECKey.Q.ToGroupElementJacobian() + Bm.ECKey.Q;

		// "Encode P_mn as a BIP341 taproot output"
		var xOnlyPubkey = new ECXOnlyPubKey(pmn.ToGroupElement(), null).ToBytes();
		var taprootPubKey = new TaprootPubKey(xOnlyPubkey);

#if NET8_0_OR_GREATER
		var s = Convert.ToHexString(xOnlyPubkey);
#endif

		return taprootPubKey;
	}

	/// <seealso href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#creating-outputs">
	/// Step 2: For each private key a_i corresponding to a BIP341 taproot output, check that the private key produces a point with an even Y coordinate and negate the private key if not.
	/// </seealso>
	private static Key? SumPrivateKeys(Utxo[] utxos)
	{
		// "Let a = a_1 + a_2 + ... + a_n, where each a_i has been negated if necessary"
		var sum = Scalar.Zero;

		foreach (var utxo in utxos)
		{
			var pk = ECPrivKey.Create(utxo.SigningKey.ToBytes());
			var k = pk.sec;

			if (utxo.ScriptPubKey.IsScriptType(ScriptType.Taproot))
			{
				pk.CreateXOnlyPubKey(out bool parity);
				if (parity)
				{
					k = k.Negate();
				}
			}

			sum = sum.Add(k);
		}

		if (sum.IsZero)
		{
			// "If a = 0, fail"
			// No outputs can be created. Stop.
			return null;
		}

		return new Key(sum.ToBytes());
	}

	// Let A = A1 + A2 + ... + An
	private static PubKey SumPublicKeys(IEnumerable<PubKey> pubKeys)
	{
		var bytes = new ECXOnlyPubKey(pubKeys.Aggregate(GEJ.Infinity, (acc, key) => acc + key.ECKey.Q).ToGroupElement(), null).ToBytes();
		return new PubKey(bytes);
	}

	private static byte[] TaggedHash(string tag, byte[] data)
	{
		var tagHash = Hashes.SHA256(Encoding.UTF8.GetBytes(tag));
		var concat = tagHash.Concat(tagHash).Concat(data);
		return Hashes.SHA256(concat);
	}

	private static byte[] Serialize32(uint i)
	{
		var result = new byte[4];
		BitConverter.GetBytes(i).CopyTo(result, 0);
		if (BitConverter.IsLittleEndian)
		{
			Array.Reverse(result);
		}

		return result;
	}
}

public class Utxo
{
	public Utxo(OutPoint OutPoint, Key SigningKey, Script ScriptPubKey)
	{
		this.OutPoint = OutPoint;
		this.SigningKey = SigningKey;
		this.ScriptPubKey = ScriptPubKey;
	}

	public OutPoint OutPoint { get; }
	public Key SigningKey { get; }
	public Script ScriptPubKey { get; }
}

static class LinqExtensions
{
	public static IEnumerable<T> DropNulls<T>(this IEnumerable<T?> source) where T: class =>
		source.Where(x => x is not null).Select(x => x!);
}
#endif
