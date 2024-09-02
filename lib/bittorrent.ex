defmodule Bittorrent.CLI do
  def main(argv) do
      case argv do
          ["decode" | [encoded_str | _]] ->
              decoded_str = Bencode.decode(encoded_str)
              IO.puts(Jason.encode!(decoded_str))
          [command | _] ->
              IO.puts("Unknown command: #{command}")
              System.halt(1)
          [] ->
              IO.puts("Usage: your_bittorrent.sh <command> <args>")
              System.halt(1)
      end
  end
end

defmodule Bencode do
  def decode(encoded_value) when is_binary(encoded_value) do
    binary_data = :binary.bin_to_list(encoded_value)

    case find_colon_index(binary_data) do
      nil ->
        case find_integer_start(binary_data) do
          nil ->
            IO.puts("Neither ':' nor 'i' character found in the binary")
            nil
          integer_start_index ->
            decode_integer(binary_data, integer_start_index)
        end
      colon_index ->
        decode_string(binary_data, colon_index)
    end
  end

  def decode(_), do: "Invalid encoded value: not binary"

  defp find_colon_index(binary_data) do
    Enum.find_index(binary_data, fn char -> char == 58 end)
  end

  defp find_integer_start(binary_data) do
    Enum.find_index(binary_data, fn char -> char == 105 end)
  end

  defp decode_string(binary_data, index) do
    rest = Enum.slice(binary_data, index + 1..-1)
    List.to_string(rest)
  end

  defp decode_integer(binary_data, index) do
    rest = Enum.slice(binary_data, index+1..-2)
    List.to_integer(rest)
  end
end
