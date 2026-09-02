#if HAS_SPAN
#nullable enable
using NBitcoin.BIP352;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace NBitcoin.Tests;

public class SilentPaymentTests
{
	[Theory]
	[MemberData(nameof(SilentPaymentTestVector.TestCases), MemberType = typeof(SilentPaymentTestVector))]
	public void TestVectors(SilentPaymentTestVector test)
	{
		// Test sending functionality
		foreach (var sending in test.Sending)
		{
			var given = sending.Given;
			try
			{
				var utxos = given.Vin
					.Select(x => new Utxo(
						OutPoint: new OutPoint(uint256.Parse(x.TxId), x.Vout),
						SigningKey: new Key(Encoders.Hex.DecodeData(x.PrivateKey)),
						ScriptPubKey: Script.FromHex(x.PrevOut.ScriptPubKey.Hex)))
					.ToArray();

				// Parse recipients and verify that the scan and spend keys match the expected values
				var recipients = new List<SilentPaymentAddress>();

				foreach (var recipient in given.Recipients)
				{
					var silentPaymentAddress = SilentPaymentAddress.Parse(recipient.Address, Network.Main);

					Assert.Equal(recipient.ScanPubKey, silentPaymentAddress.ScanKey.ToHex());
					Assert.Equal(recipient.SpendPubKey, silentPaymentAddress.SpendKey.ToHex());

					recipients.Add(silentPaymentAddress);
				}

				var xonlyPks = SilentPayment.GetPubKeys(recipients, utxos);
				var actual = xonlyPks.SelectMany(x => x.Value).Select(x => Encoders.Hex.EncodeData(x.ToBytes()));

				var expected = sending.Expected;
				Assert.Subset(expected.Outputs.SelectMany(x => x).ToHashSet(), actual.ToHashSet());
			}
			catch (ArgumentException e) when (e.Message.Contains("Invalid ec private key") && test.Comment.Contains("point at infinity"))
			{
				// ignore because it is expected to fail;
			}
		}

		// Test receiving functionality

		// message and auxiliary data used in signature
		// see: https://github.com/bitcoinops/taproot-workshop/blob/master/1.1-schnorr-signatures.ipynb
		var msg = Crypto.Hashes.SHA256(Encoders.ASCII.DecodeData("message"));
		var aux = Crypto.Hashes.SHA256(Encoders.ASCII.DecodeData("random auxiliary data"));

		foreach (var receiving in test.Receiving)
		{
			var given = receiving.Given;
			var expected = receiving.Expected;
			try
			{
				var prevOuts = given.Vin.Select(x => OutPoint.Parse(x.TxId + "-" + x.Vout)).ToArray();
				var pubKeys = given.Vin.Select(ExtractPubKey).DropNulls().ToArray();
				if (pubKeys.Length == 0)
				{
					continue; // if there are no pubkeys then nothing can be done
				}

				// Parse key material (scan and spend keys)
				using var scanKey = ParsePrivKey(given.Key_Material.ScanPrivKey);
				using var spendKey = ParsePrivKey(given.Key_Material.SpendPrivKey);

				// Addresses
				var baseAddress = new SilentPaymentAddress(0, scanKey.PubKey, spendKey.PubKey);

				// Creates a lookup table Dic<SilentPaymentAddress, (ECPrivKey labelSecret, ECPubKey labelPubKey)>
				var addressesTable = given.Labels
					.Select(label => SilentPayment.CreateLabel(scanKey, (uint)label))
					.Select(labelSecret => new LabelInfo.Full(labelSecret, labelSecret.PubKey))
					.Select(labelInfo => (LabelInfo: (LabelInfo)labelInfo, Address: baseAddress.DeriveAddressForLabel(labelInfo.PubKey))) // each label has a different address
					.Prepend((LabelInfo: new LabelInfo.None(), baseAddress))
					.ToDictionary(x => x.Address, x => x.LabelInfo);
				var addresses = addressesTable.Keys.ToArray();
				var expectedAddresses = expected.Addresses.Select(x => SilentPaymentAddress.Parse(x, Network.Main));
				Assert.Equal(expectedAddresses, addresses);

				var sharedSecret = SilentPayment.ComputeSharedSecretReceiver(prevOuts, pubKeys, scanKey);

				// Outputs
				var givenOutputPubKeys = given.Outputs.Select(ParseXOnlyPubKey).ToArray();
				var detectedOutputPubKeys = SilentPayment.GetPubKeys(addresses, sharedSecret, givenOutputPubKeys);
				var detectedOutputs = detectedOutputPubKeys.Select(x => Encoders.Hex.EncodeData(x.PubKey.ToBytes())).ToHashSet();
				var expectedOutputs = expected.Outputs.Select(x => x.PubKey).ToHashSet();

				Assert.Equal(detectedOutputs, expectedOutputs);

				// Tweak Key

				// Enrich the detected output xonlypubkeys with corresponding label info (secret and public key)
				var detectedXonlyWithLabelInfo = detectedOutputPubKeys
					.Select(x => (x.Address, x.PubKey, LabelInfo: addressesTable[x.Address]))
					.ToArray();

				// Compute tweakKey for each detected output
				var tweakKeys = detectedXonlyWithLabelInfo
					.Select((pk, k) =>
					{
						var tk = SilentPayment.TweakKey(sharedSecret, (uint)k);
						return pk.LabelInfo switch
						{
							LabelInfo.None => (pk.PubKey, TweakKey: tk),
							LabelInfo.Full info => (pk.PubKey, TweakKey: new Key(tk._ECKey.TweakAdd(info.Secret.ToBytes()).sec.ToBytes())),
							_ => throw new ArgumentException("Unknown label type")
						};
					})
					.ToArray();

				var detectedTweakKeys = tweakKeys.Select(x => Encoders.Hex.EncodeData(x.TweakKey.ToBytes())).ToHashSet();
				var expectedTweakKeys = expected.Outputs.Select(o => o.PrivKeyTweak).ToHashSet();

				Assert.Equal(expectedTweakKeys, detectedTweakKeys);

				// Signature
				var expectedSignature = expected.Outputs.Select(o => o.Signature).ToHashSet();
				var tweakKeyMap = tweakKeys.ToDictionary(x => x.PubKey, x => x.TweakKey);
				var computedSignatures = detectedOutputPubKeys
					.Select(x => (x.Address, x.PubKey, TweakKey: tweakKeyMap[x.PubKey]))
					.Select(x => SilentPayment.ComputePrivKey(spendKey, x.TweakKey))
					.Select(x => x._ECKey.SignBIP340(msg, aux))
					.Select(x => Encoders.Hex.EncodeData(x.ToBytes()))
					.ToHashSet();

				Assert.Equal(expectedSignature, computedSignatures);
			}
			catch (InvalidOperationException e) when (e.Message.Contains("infinite") && test.Comment.Contains("point at infinity"))
			{
				// ignore because it is expected to fail;
			}
		}

		PubKey ParseXOnlyPubKey(string pk) =>
			new(Encoders.Hex.DecodeData(pk));

		Key ParsePrivKey(string pk) =>
			new(Encoders.Hex.DecodeData(pk));
	}


	private PubKey? ExtractPubKey(ReceivingVin vin)
	{
		var spk = Script.FromHex(vin.PrevOut.ScriptPubKey.Hex);
		var scriptSig = Script.FromHex(vin.ScriptSig);
		var txInWitness = string.IsNullOrEmpty(vin.TxInWitness) ? null : new WitScript(Encoders.Hex.DecodeData(vin.TxInWitness));
		return SilentPayment.ExtractPubKey(scriptSig, txInWitness, spk);
	}
}

public class ScriptPubKey(string Hex)
{
	public string Hex { get; } = Hex;
}

public class Output(ScriptPubKey ScriptPubKey)
{
	public ScriptPubKey ScriptPubKey { get; } = ScriptPubKey;
}

public class ReceivingExpectedOutput(string PrivKeyTweak, string PubKey, string Signature)
{
	[JsonProperty("priv_key_tweak")]
	public string PrivKeyTweak { get; } = PrivKeyTweak;

	[JsonProperty("pub_key")]
	public string PubKey { get; } = PubKey;

	[JsonProperty("signature")]
	public string Signature { get; } = Signature;
}

public class ReceivingVin(string TxId, int Vout, Output PrevOut, string? ScriptSig, string? TxInWitness)
{
	public string TxId { get; } = TxId;
	public int Vout { get; } = Vout;
	public Output PrevOut { get; } = PrevOut;
	public string? ScriptSig { get; } = ScriptSig;
	public string? TxInWitness { get; } = TxInWitness;
}

public class SendingVin(string TxId, int Vout, string PrivateKey, Output PrevOut)
{
	[JsonProperty("txid")]
	public string TxId { get; } = TxId;

	[JsonProperty("vout")]
	public int Vout { get; } = Vout;

	[JsonProperty("private_key")]
	public string PrivateKey { get; } = PrivateKey;

	[JsonProperty("prevout")]
	public Output PrevOut { get; } = PrevOut;
}

public class Recipient(string Address, string ScanPubKey, string SpendPubKey)
{
	[JsonProperty("address")]
	public string Address { get; } = Address;

	[JsonProperty("scan_pub_key")]
	public string ScanPubKey { get; } = ScanPubKey;

	[JsonProperty("spend_pub_key")]
	public string SpendPubKey { get; } = SpendPubKey;
}

public class SendingGiven(SendingVin[] Vin, Recipient[] Recipients)
{
	public SendingVin[] Vin { get; } = Vin;
	public Recipient[] Recipients { get; } = Recipients;
}

public class KeyMaterial(string SpendPrivKey, string ScanPrivKey)
{
	[JsonProperty("spend_priv_key")]
	public string SpendPrivKey { get; } = SpendPrivKey;

	[JsonProperty("scan_priv_key")]
	public string ScanPrivKey { get; } = ScanPrivKey;
}

public class ReceivingGiven(ReceivingVin[] Vin, string[] Outputs, KeyMaterial KeyMaterial, int[] Labels)
{
	public ReceivingVin[] Vin { get; } = Vin;
	public string[] Outputs { get; } = Outputs;
	public KeyMaterial Key_Material { get; } = KeyMaterial;
	public int[] Labels { get; } = Labels;
}

public class SendingExpected(string[][] Outputs, string[] SharedSecrets, string InputPrivateKeySum, string[] InputPubKeys)
{
	public string[][] Outputs { get; } = Outputs;

	[JsonProperty("shared_secrets")]
	public string[] SharedSecrets { get; } = SharedSecrets;

	[JsonProperty("input_private_key_sum")]
	public string InputPrivateKeySum { get; } = InputPrivateKeySum;

	[JsonProperty("input_pub_keys")]
	public string[] InputPubKeys { get; } = InputPubKeys;
}

public class ReceivingExpected(string[] Addresses, ReceivingExpectedOutput[] Outputs, string Tweak, string SharedSecret, string InputPubKeySum)
{
	public string[] Addresses { get; } = Addresses;
	public ReceivingExpectedOutput[] Outputs { get; } = Outputs;

	[JsonProperty("tweak")]
	public string Tweak { get; } = Tweak;

	[JsonProperty("shared_secret")]
	public string SharedSecret { get; } = SharedSecret;

	[JsonProperty("input_pub_key_sum")]
	public string InputPubKeySum { get; } = InputPubKeySum;
}

public class Sending(SendingGiven Given, SendingExpected Expected)
{
	public SendingGiven Given { get; } = Given;
	public SendingExpected Expected { get; } = Expected;
}

public class Receiving(ReceivingGiven Given, ReceivingExpected Expected)
{
	public ReceivingGiven Given { get; } = Given;
	public ReceivingExpected Expected { get; } = Expected;
}

public class SilentPaymentTestVector(string Comment, Sending[] Sending, Receiving[] Receiving)
{
	public string Comment { get; } = Comment;
	public Sending[] Sending { get; } = Sending;
	public Receiving[] Receiving { get; } = Receiving;

	private static SilentPaymentTestVector[] VectorsData() =>
		JsonConvert.DeserializeObject<SilentPaymentTestVector[]>(File.ReadAllText("./data/SilentPaymentTestVectors.json"))!;

	public static readonly TheoryData<SilentPaymentTestVector> TestCases = new(VectorsData());

	public override string ToString() => Comment;
}

public abstract class LabelInfo
{
	public class Full(Key Secret, PubKey PubKey) : LabelInfo
	{
		public Key Secret { get; } = Secret;
		public PubKey PubKey { get; } = PubKey;
	}

	public class None : LabelInfo;
}
#endif
