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

defmodule YourBittorrentClient do
  require Logger

  def start_download(torrent_file) do
    peer_id = generate_peer_id()
    # Or any port you want to use
    port = 6881

    case BitTorrentTracker.get_peers(torrent_file, peer_id, port) do
      {:ok, peers} -> {:ok, peers}
      {:error, reason} -> {:error, reason}
    end
  end

  def generate_peer_id do
    # Generate a unique 20-byte peer ID
    "00112233445566778899"
  end

  def perform_handshake(torrent_file, ip, port) do
    Logger.info("Starting handshake with #{ip}:#{port}")

    case TorrentParser.parse_file(torrent_file) do
      {:ok, %{info_hash: info_hash}} ->
        peer_id = generate_peer_id()
        raw_info_hash = Base.decode16!(info_hash, case: :lower)
        handshake_msg = create_handshake_message(raw_info_hash, peer_id)

        Logger.info("Connecting to peer")

        with {:ok, socket} <-
               :gen_tcp.connect(String.to_charlist(ip), port, [:binary, active: false], 10000),
             :ok <- :gen_tcp.send(socket, handshake_msg),
             {:ok, response} <- :gen_tcp.recv(socket, 68, 10000) do
          peer_id = binary_part(response, 48, 20)
          Logger.info("Handshake successful. Peer ID: #{Base.encode16(peer_id, case: :lower)}")
          # Ensure this is returned
          {:ok, socket}
        else
          {:error, reason} ->
            Logger.error("Handshake failed: #{inspect(reason)}")
            {:error, "Handshake failed: #{inspect(reason)}"}
        end

      {:error, reason} ->
        Logger.error("Error parsing torrent file: #{inspect(reason)}")
        {:error, "Failed to parse torrent file: #{inspect(reason)}"}
    end
  end

  def create_handshake_message(info_hash, peer_id) do
    protocol = "BitTorrent protocol"

    <<
      byte_size(protocol),
      protocol::binary,
      0::size(64),
      info_hash::binary,
      peer_id::binary
    >>
  end
end

defmodule PieceDownloader do
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
end

defmodule BitTorrentTracker do
  require Logger

  @moduledoc """
  Handles communication with BitTorrent trackers, including creating requests
  and parsing responses.
  """

  @doc """
  Sends a request to the tracker and returns the parsed peer information.
  """
  def get_peers(torrent_file, peer_id, port) do
    with {:ok, torrent_info} <- TorrentParser.parse_file(torrent_file),
         tracker_url <- construct_tracker_url(torrent_info, peer_id, port),
         {:ok, response} <- make_tracker_request(tracker_url),
         {:ok, peers} <- parse_tracker_response(response) do
      {:ok, peers}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Constructs the tracker URL with all necessary parameters.
  """
  def construct_tracker_url(torrent_info, peer_id, port) do
    query_params =
      URI.encode_query(%{
        info_hash: get_raw_info_hash(torrent_info.info_hash),
        peer_id: peer_id,
        port: port,
        uploaded: 0,
        downloaded: 0,
        left: torrent_info.length,
        compact: 1
      })

    "#{torrent_info.tracker_url}?#{query_params}"
  end

  @doc """
  URL encodes the info hash for use in the tracker request.
  """
  def get_raw_info_hash(hex_info_hash) do
    hex_info_hash
    |> Base.decode16!(case: :lower)
  end

  @doc """
  Makes an HTTP GET request to the tracker.
  """
  def make_tracker_request(url) do
    case HTTPoison.get(url) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        {:ok, body}

      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "HTTP request failed with status code: #{status_code}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Parses the bencoded response from the tracker.
  """
  def parse_tracker_response(response_body) do
    case Bencode.decode(response_body) do
      {:ok, response, _rest} when is_map(response) ->
        case response do
          %{"failure reason" => reason} ->
            {:error, "Tracker returned error: #{reason}"}

          %{"warning message" => warning} ->
            IO.puts("Tracker warning: #{warning}")
            parse_successful_response(response)

          _ ->
            parse_successful_response(response)
        end

      {:ok, _, _} ->
        {:error, "Tracker response is not a dictionary"}

      {:error, reason} ->
        {:error, "Failed to decode tracker response: #{reason}"}
    end
  end

  defp parse_successful_response(response) do
    case response do
      %{"peers" => peers_binary} when is_binary(peers_binary) ->
        parsed_peers = parse_compact_peers(peers_binary)
        {:ok, parsed_peers}

      %{"peers" => peers_list} when is_list(peers_list) ->
        parsed_peers = parse_dictionary_model_peers(peers_list)
        {:ok, parsed_peers}

      _ ->
        {:error, "Invalid or missing peers data in tracker response"}
    end
  end

  defp parse_compact_peers(peers_binary) do
    for <<a, b, c, d, port::16 <- peers_binary>> do
      ip = "#{a}.#{b}.#{c}.#{d}"
      {ip, port}
    end
  end

  defp parse_dictionary_model_peers(peers_list) do
    Enum.map(peers_list, fn peer ->
      {peer["ip"], peer["port"]}
    end)
  end
end

defmodule TorrentParser do
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
