defmodule Bittorrent.CLI do
  alias Bittorrent.{
    PieceDownloader,
    YourBittorrentClient,
    Bencode,
    TorrentParser
  }

  def main(argv) do
    case argv do
      [command | args] ->
        execute_command(command, args)

      [] ->
        IO.puts("Usage: your_bittorrent.sh <command> <args>")
        System.halt(1)
    end
  end

  defp execute_command("download", ["-o", output_file, torrent_file]) do
    case PieceDownloader.download_file(torrent_file, output_file) do
      {:ok, message} ->
        IO.puts(message)

      {:error, reason} ->
        IO.puts("Error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp execute_command("download_piece", ["-o", output_file, torrent_file, piece_index]) do
    piece_index = String.to_integer(piece_index)

    case PieceDownloader.download_piece(torrent_file, piece_index, output_file) do
      {:ok, message} ->
        IO.puts(message)

      {:error, reason} ->
        IO.puts("Error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp execute_command("handshake", [torrent_file, peer_address]) do
    [ip, port] = String.split(peer_address, ":")
    port = String.to_integer(port)
    YourBittorrentClient.perform_handshake(torrent_file, ip, port)
  end

  defp execute_command("peers", [torrent_file]) do
    case YourBittorrentClient.start_download(torrent_file) do
      {:ok, peers} ->
        IO.puts("Peers:")

        Enum.each(peers, fn {ip, port} ->
          IO.puts("#{ip}:#{port}")
        end)

      {:error, reason} ->
        IO.puts("Error: #{reason}")
    end
  end

  defp execute_command("info", [torrent_file]) do
    case TorrentParser.parse_file(torrent_file) do
      {:ok,
       %{
         tracker_url: tracker_url,
         length: length,
         info_hash: info_hash,
         piece_length: piece_length,
         piece_hashes: piece_hashes
       }} ->
        IO.puts("Tracker URL: #{tracker_url}")
        IO.puts("Length: #{length}")
        IO.puts("Info Hash: #{info_hash}")
        IO.puts("Piece Length: #{piece_length}")
        IO.puts("Piece Hashes:")
        Enum.each(piece_hashes, &IO.puts/1)

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
