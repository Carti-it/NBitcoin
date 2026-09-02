#if HAS_SPAN
#nullable enable
using System;
using NBitcoin.DataEncoders;

namespace NBitcoin.BIP352;

public class SilentPaymentBech32Encoder : Bech32Encoder
{
	public SilentPaymentBech32Encoder(byte[] hrp) : base(hrp)
	{
		StrictLength = false;
	}

	public byte[] FromBase32(ReadOnlySpan<byte> data) =>
		ConvertBits(data, 5, 8, false);
}
#endif
