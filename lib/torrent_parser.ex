defmodule Bittorrent.TorrentParser do
  alias Bittorrent.Bencode

  def parse_file(path) do
    with {:ok, binary} <- File.read(path),
         {:ok, decoded, _rest} <- Bencode.decode(binary),
         {:ok, tracker_url} <- Map.fetch(decoded, "announce"),
         {:ok, info} <- Map.fetch(decoded, "info"),
         {:ok, length} <- Map.fetch(info, "length"),
         {:ok, piece_length} <- Map.fetch(info, "piece length"),
         {:ok, pieces} <- Map.fetch(info, "pieces"),
         info_hash <- calculate_info_hash(info),
         piece_hashes <- split_piece_hashes(pieces) do
      {:ok,
       %{
         tracker_url: tracker_url,
         length: length,
         info_hash: info_hash,
         piece_length: piece_length,
         piece_hashes: piece_hashes
       }}
    else
      {:error, reason} -> {:error, "Failed to parse torrent data: #{inspect(reason)}"}
      :error -> {:error, "Missing required fields in torrent file"}
    end
  end

  defp calculate_info_hash(info) do
    case Bento.encode(info) do
      {:ok, bencoded_info} ->
        bencoded_info
        |> sha1_hash()
        |> Base.encode16(case: :lower)

      {:error, reason} ->
        raise "Failed to encode info dictionary: #{inspect(reason)}"
    end
  end

  defp sha1_hash(data) do
    :crypto.hash(:sha, data)
  end

  defp split_piece_hashes(pieces) do
    for <<hash::binary-size(20) <- pieces>>, do: Base.encode16(hash, case: :lower)
  end
end
