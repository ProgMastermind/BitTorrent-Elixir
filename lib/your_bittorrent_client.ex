defmodule Bittorrent.YourBittorrentClient do
  alias Bittorrent.{
    BitTorrentTracker,
    TorrentParser
  }

  require Logger

  def get_peers(torrent_file) do
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
