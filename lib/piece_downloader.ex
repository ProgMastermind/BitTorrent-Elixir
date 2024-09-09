defmodule Bittorrent.PieceDownloader do
  alias Bittorrent.{
    YourBittorrentClient,
    BitTorrentTracker,
    TorrentParser
  }

  require Logger
  # 16 KiB
  @block_size 16 * 1024

  def download_piece(torrent_file, piece_index, output_file) do
    Logger.info("Starting download of piece #{piece_index}")

    with {:ok, torrent_info} <- TorrentParser.parse_file(torrent_file),
         {:ok, {ip, port}} <- get_peer(torrent_file),
         {:ok, socket} <- YourBittorrentClient.perform_handshake(torrent_file, ip, port),
         :ok <- wait_for_bitfield(socket),
         :ok <- send_interested(socket),
         :ok <- wait_for_unchoke(socket),
         {:ok, piece_data} <- download_piece_data(socket, torrent_info, piece_index),
         :ok <- verify_piece(piece_data, torrent_info.piece_hashes, piece_index),
         :ok <- write_piece_to_file(piece_data, output_file) do
      :gen_tcp.close(socket)
      {:ok, "Piece #{piece_index} downloaded to #{output_file}."}
    else
      {:error, reason} ->
        Logger.error("Error during download: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp write_piece_to_file(piece_data, output_file) do
    directory = Path.dirname(output_file)

    with :ok <- File.mkdir_p(directory),
         :ok <- File.write(output_file, piece_data, [:write, :binary]) do
      :ok
    else
      error ->
        IO.puts("Error writing file: #{inspect(error)}")
        error
    end
  end

  defp get_peer(torrent_file) do
    peer_id = YourBittorrentClient.generate_peer_id()

    case BitTorrentTracker.get_peers(torrent_file, peer_id, 6881) do
      {:ok, [peer | _]} -> {:ok, peer}
      {:ok, []} -> {:error, "No peers available"}
      error -> error
    end
  end

  defp wait_for_bitfield(socket) do
    case receive_message(socket) do
      {:ok, 5, _payload} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp send_interested(socket) do
    send_message(socket, 2, <<>>)
  end

  defp wait_for_unchoke(socket) do
    case receive_message(socket) do
      {:ok, 1, <<>>} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp download_piece_data(socket, torrent_info, piece_index) do
    piece_length = get_piece_length(torrent_info, piece_index)
    download_blocks(socket, piece_index, piece_length)
  end

  defp get_piece_length(torrent_info, piece_index) do
    if piece_index == div(torrent_info.length, torrent_info.piece_length) do
      rem(torrent_info.length, torrent_info.piece_length)
    else
      torrent_info.piece_length
    end
  end

  defp download_blocks(socket, piece_index, piece_length) do
    num_blocks = div(piece_length + @block_size - 1, @block_size)

    Enum.reduce_while(0..(num_blocks - 1), {:ok, <<>>}, fn block_index, {:ok, acc} ->
      begin = block_index * @block_size
      length = min(@block_size, piece_length - begin)

      with :ok <- send_request(socket, piece_index, begin, length),
           {:ok, block_data} <- receive_piece(socket, piece_index, begin) do
        {:cont, {:ok, acc <> block_data}}
      else
        error -> {:halt, error}
      end
    end)
  end

  defp send_request(socket, index, begin, length) do
    payload = <<index::32, begin::32, length::32>>
    send_message(socket, 6, payload)
  end

  defp receive_piece(socket, expected_index, expected_begin) do
    case receive_message(socket) do
      {:ok, 7, <<^expected_index::32, ^expected_begin::32, block::binary>>} ->
        {:ok, block}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp send_message(socket, id, payload) do
    length = byte_size(payload) + 1
    :gen_tcp.send(socket, <<length::32, id, payload::binary>>)
  end

  defp receive_message(socket) do
    with {:ok, <<length::32>>} <- :gen_tcp.recv(socket, 4, 10000),
         {:ok, <<id, payload::binary>>} <- :gen_tcp.recv(socket, length, 10000) do
      {:ok, id, payload}
    end
  end

  defp verify_piece(piece_data, piece_hashes, piece_index) do
    actual_hash = :crypto.hash(:sha, piece_data) |> Base.encode16(case: :lower)
    expected_hash = Enum.at(piece_hashes, piece_index)
    if actual_hash == expected_hash, do: :ok, else: {:error, "Piece hash mismatch"}
  end

  def download_file(torrent_file, output_file) do
    with {:ok, torrent_info} <- TorrentParser.parse_file(torrent_file),
         {:ok, {ip, port}} <- get_peer(torrent_file),
         {:ok, socket} <- YourBittorrentClient.perform_handshake(torrent_file, ip, port),
         :ok <- wait_for_bitfield(socket),
         :ok <- send_interested(socket),
         :ok <- wait_for_unchoke(socket) do
      piece_count = length(torrent_info.piece_hashes)

      result =
        Enum.reduce_while(0..(piece_count - 1), {:ok, []}, fn piece_index, {:ok, acc} ->
          case download_and_verify_piece(socket, torrent_info, piece_index) do
            {:ok, piece_data} -> {:cont, {:ok, [piece_data | acc]}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)

      :gen_tcp.close(socket)

      case result do
        {:ok, pieces} ->
          combined_data = Enum.reverse(pieces) |> IO.iodata_to_binary()
          write_file(combined_data, output_file)

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp download_and_verify_piece(socket, torrent_info, piece_index) do
    with {:ok, piece_data} <- download_piece_data(socket, torrent_info, piece_index),
         :ok <- verify_piece(piece_data, torrent_info.piece_hashes, piece_index) do
      {:ok, piece_data}
    end
  end

  defp write_file(data, output_file) do
    case File.write(output_file, data) do
      :ok -> {:ok, "Downloaded #{Path.basename(output_file)} to #{output_file}."}
      {:error, reason} -> {:error, "Failed to write file: #{inspect(reason)}"}
    end
  end
end
