defmodule Bittorrent.BitTorrentTracker do
  alias Bittorrent.{TorrentParser, Bencode}

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
