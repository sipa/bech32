# Copyright (c) 2017 Adán Sánchez de Pedro Crespo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

defmodule SegwitAddr do
  use Bitwise

  @moduledoc ~S"""
  Encode and decode BIP-0173 compliant SegWit addresses.
  """

  @doc ~S"""
  Encode a SegWit address.

  ## Examples

      iex> SegwitAddr.encode("bc", "0014751e76e8199196d454941c45d1b3a323f1433bd6")
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

      iex> SegwitAddr.encode("bc", 0, [117, 30, 118, 232, 25, 145, 150, 212,
      ...> 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214])
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
  """
  @spec encode(String.t, integer, list(integer)) :: String.t
  def encode(hrp, version, program) when is_list(program) do
    Bech32.encode(hrp, [version] ++ convert_bits(program, 8, 5))
  end

  @spec encode(String.t, String.t) :: String.t
  def encode(hrp, program) when is_binary(program) do
    <<version, _size, program::binary>> = Base.decode16!(program, case: :mixed)
    program
      |> :binary.bin_to_list
      |> (&(encode(hrp, version, &1))).()
  end

  @doc ~S"""
  Decode a SegWit address.

  ## Examples

      iex> SegwitAddr.decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
      {:ok, {"bc", 0, [117, 30, 118, 232, 25, 145, 150, 212,
      84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214]}}
  """
  @spec decode(String.t)
  :: {:ok, {pos_integer, list(integer)}} | {:error,  String.t}
  def decode(addr) do
    case Bech32.decode(addr) do
      {:ok, {hrp, data}} ->
        [version | encoded] = data
        program = convert_bits(encoded, 5, 8, false)
        {:ok, {hrp, version, program}}
      error -> error
    end
  end

  @doc ~S"""
  Encode a witness program into a hexadecimal ScriptPubKey.

  ## Examples

      iex> SegwitAddr.to_script_pub_key(0, [117, 30, 118, 232, 25, 145, 150,
      ...> 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214])
      "0014751e76e8199196d454941c45d1b3a323f1433bd6"
  """
  @spec to_script_pub_key(pos_integer, list(integer)) :: String.t
  def to_script_pub_key(version, program) do
    [
      if version == 0 do 0 else version + 0x50 end,
      Enum.count(program) | program
    ]
      |> :binary.list_to_bin()
      |> Base.encode16(case: :lower)
  end

  # General power-of-2 base conversion.
  defp convert_bits(data, from, to, pad \\ true) do
    max_v = (1 <<< to) - 1
    if (Enum.find(data, fn (c) -> c < 0 || (c >>> from) != 0 end)) do
      nil
    else
      {acc, bits, ret} = Enum.reduce(
        data,
        {0, 0, []},
        fn (value, {acc, bits, ret}) ->
          acc = ((acc <<< from) ||| value)
          bits = bits + from
          {bits, ret} = convert_bits_loop(to, max_v, acc, bits, ret)
          {acc, bits, ret}
        end
      )
      if (pad && bits > 0) do
        ret ++ [(acc <<< (to - bits)) &&& max_v]
      else
        if (bits > from || ((acc <<< (to - bits)) &&& max_v) > 0) do
          nil
        else
          ret
        end
      end
    end
  end

  # Recursive version of the inner loop of the convert_bits function
  defp convert_bits_loop(to, max_v, acc, bits, ret) do
    if (bits >= to) do
      bits = bits - to
      ret = ret ++ [(acc >>> bits) &&& max_v]
      convert_bits_loop(to, max_v, acc, bits, ret)
    else
      {bits, ret}
    end
  end

end
