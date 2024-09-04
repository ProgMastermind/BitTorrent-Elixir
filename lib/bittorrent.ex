defmodule Bittorrent.CLI do
  def main(argv) do
    case argv do
      [command | args] ->
        execute_command(command, args)

      [] ->
        IO.puts("Usage: your_bittorrent.sh <command> <args>")
        System.halt(1)
    end
  end

  defp execute_command("info", [torrent_file]) do
    case TorrentParser.parse_file(torrent_file) do
      {:ok, %{tracker_url: tracker_url, length: length}} ->
        IO.puts("Tracker URL: #{tracker_url}")
        IO.puts("Length: #{length}")

      {:error, message} ->
        IO.puts("Error: #{message}")
    end
  end

  defp execute_command("decode", [encoded_str]) do
    case Bencode.decode(encoded_str) do
      {:ok, decoded_value, _rest} -> IO.puts(Jason.encode!(decoded_value))
      {:error, message} -> IO.puts("Error: #{message}")
      _ -> IO.puts("Error: Unexpected decoding result")
    end
  end

  defp execute_command(command, _args) do
    IO.puts("Unknown command: #{command}")
  end
end

defmodule TorrentParser do
  def parse_file(path) do
    with {:ok, binary} <- File.read(path),
         {:ok, decoded, _rest} <- Bencode.decode(binary),
         {:ok, tracker_url} <- Map.fetch(decoded, "announce"),
         {:ok, info} <- Map.fetch(decoded, "info"),
         {:ok, length} <- Map.fetch(info, "length") do
      {:ok, %{tracker_url: tracker_url, length: length}}
    else
      {:error, reason} -> {:error, "Failed to parse torrent file: #{inspect(reason)}"}
      :error -> {:error, "Missing required fields in torrent file"}
    end
  end
end

defmodule Bencode do
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
