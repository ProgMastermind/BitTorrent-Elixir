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
  def start_download(torrent_file) do
    peer_id = generate_peer_id()
    # Or any port you want to use
    port = 6881

    case BitTorrentTracker.get_peers(torrent_file, peer_id, port) do
      {:ok, peers} -> {:ok, peers}
      {:error, reason} -> {:error, reason}
    end
  end

  defp generate_peer_id do
    # Generate a unique 20-byte peer ID
    "00112233445566778899"
  end

  def perform_handshake(torrent_file, ip, port) do
    case TorrentParser.parse_file(torrent_file) do
      {:ok, %{info_hash: info_hash}} ->
        peer_id = generate_peer_id()
        raw_info_hash = Base.decode16!(info_hash, case: :lower)
        handshake_msg = create_handshake_message(raw_info_hash, peer_id)

        case :gen_tcp.connect(String.to_charlist(ip), port, [:binary, active: false]) do
          {:ok, socket} ->
            :ok = :gen_tcp.send(socket, handshake_msg)

            case :gen_tcp.recv(socket, 68) do
              {:ok, response} ->
                peer_id = binary_part(response, 48, 20)
                IO.puts("Peer ID: #{Base.encode16(peer_id, case: :lower)}")

              {:error, reason} ->
                IO.puts("Error receiving handshake: #{inspect(reason)}")
            end

            :gen_tcp.close(socket)

          {:error, reason} ->
            IO.puts("Error connecting to peer: #{inspect(reason)}")
        end

      {:error, reason} ->
        IO.puts("Error parsing torrent file: #{inspect(reason)}")
    end
  end

  defp create_handshake_message(info_hash, peer_id) do
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
      {:error, reason} -> {:error, "Failed to parse torrent file: #{inspect(reason)}"}
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
