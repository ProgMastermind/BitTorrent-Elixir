defmodule Bittorrent.Bencode do
  def decode(<<"d", rest::binary>>) do
    decode_dict(rest, %{})
  end

  def decode(<<"l", rest::binary>>) do
    decode_list(rest, [])
  end

  def decode(<<"i", rest::binary>>) do
    decode_integer(rest)
  end

  def decode(<<digit, _::binary>> = data) when digit in ?0..?9 do
    decode_string(data)
  end

  def decode(_), do: {:error, "Invalid bencoded value"}

  defp decode_dict(<<"e", rest::binary>>, acc) do
    {:ok, acc, rest}
  end

  defp decode_dict(data, acc) do
    with {:ok, key, rest} <- decode_string(data),
         {:ok, value, rest} <- decode(rest) do
      decode_dict(rest, Map.put(acc, key, value))
    else
      {:error, _} = error -> error
    end
  end

  defp decode_list(<<"e", rest::binary>>, acc) do
    {:ok, Enum.reverse(acc), rest}
  end

  defp decode_list(data, acc) do
    case decode(data) do
      {:ok, value, rest} ->
        decode_list(rest, [value | acc])

      {:error, _} = error ->
        error
    end
  end

  defp decode_integer(data) do
    case Integer.parse(data) do
      {integer, <<"e", rest::binary>>} -> {:ok, integer, rest}
      _ -> {:error, "Invalid integer encoding"}
    end
  end

  defp decode_string(data) do
    case Integer.parse(data) do
      {length, <<":", rest::binary>>} ->
        if byte_size(rest) >= length do
          string_value = binary_part(rest, 0, length)
          remaining = binary_part(rest, length, byte_size(rest) - length)
          {:ok, string_value, remaining}
        else
          {:error, "String length mismatch"}
        end

      _ ->
        {:error, "Invalid string encoding"}
    end
  end
end
