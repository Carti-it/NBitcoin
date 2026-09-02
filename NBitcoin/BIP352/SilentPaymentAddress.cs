#if HAS_SPAN
#nullable enable
using System;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;

namespace NBitcoin.BIP352;

/// <seealso href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding"/>
public class SilentPaymentAddress
{
	public SilentPaymentAddress(int Version, PubKey ScanKey, PubKey SpendKey)
	{
		this.Version = Version;
		this.ScanKey = ScanKey;
		this.SpendKey = SpendKey;
	}

	public static SilentPaymentAddress Parse(string encoded, Network network)
	{
		var spEncoder = network.GetSilentPaymentBech32Encoder();
		var result = spEncoder.DecodeDataRaw(encoded, out _);
		var version = result[0];
		if (version != 0)
		{
			throw new FormatException("Unexpected version of silent payment code");
		}

		if (result.Length != 107)
		{
			throw new FormatException("Wrong length");
		}

		var data = spEncoder.FromBase32(result[1..]);
		return new SilentPaymentAddress(
			Version: 0,
			ScanKey: new PubKey(data[..33]),
			SpendKey: new PubKey(data[33..]));
	}

	public SilentPaymentAddress DeriveAddressForLabel(PubKey mG)
	{
		var bm = new ECXOnlyPubKey((SpendKey.ECKey.Q.ToGroupElementJacobian() + mG.ECKey.Q).ToGroupElement(), null);
		return new SilentPaymentAddress(Version, ScanKey,new PubKey(bm.ToBytes()));
	}

	public int Version { get; }
	public PubKey ScanKey { get; }
	public PubKey SpendKey { get; }
}
#endif
