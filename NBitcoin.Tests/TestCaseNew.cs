using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NBitcoin.Tests;

public class TestCaseNew : List<JsonElement>
{
	public static TestCaseNew[] ReadJson(string fileName)
	{
		using var fs = File.Open(fileName, FileMode.Open);

		var result = JsonSerializer.Deserialize<TestCaseNew[]>(fs) ?? [];
		for (int i = 0; i < result.Length; i++)
		{
			result[i].Index = i;
		}

		return result;
	}

	public override string ToString()
	{
		return "[" + string.Join(",", this.Select(s => Convert.ToString(s)).ToArray()) + "]";
	}

	public int Index { get; set; }
}
