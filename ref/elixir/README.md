# BIP-0173 [![Build Status](https://travis-ci.org/stampery/elixir-bip0173.svg?branch=master)](https://travis-ci.org/stampery/elixir-bip0173)

**Elixir implementation of Bitcoin's address format for native SegWit outputs.**

Upstream GitHub repository: [stampery/elixir-bip0173](https://github.com/stampery/elixir-bip0173)

## About BIP-0173 and Bech32

[BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) proposes a checksummed base32 format, "Bech32", and a standard for native segregated witness output addresses using it.

You can find more information in [the original proposal](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) by [@sipa](https://github.com/sipa) and [@gmaxwell](https://github.com/gmaxwell).

## Installation

  1. Add `bip0173` to your list of dependencies in `mix.exs`:

```elixir
  def deps do
    [{:bip0173, "~> 0.1.2"}]
  end
```

## How to use

You can find the full API reference and examples in the [online documentation at Hexdocs](https://hexdocs.pm/bip0173/api-reference.html).

### Bech32

#### Encoding data to Bech32 string
```elixir
iex> Bech32.encode("bech32", [0, 1, 2])
"bech321qpz4nc4pe"
```
```elixir
iex> Bech32.encode("bc", [0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13,
...> 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24,20, 6, 14, 30, 22])
"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
```

#### Decoding data from Bech32 string
```elixir
iex> Bech32.decode("bech321qpz4nc4pe")
{:ok, {"bech32", [0, 1, 2]}}
```
``` elixir
iex> Bech32.decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
{:ok, {"bc", [0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21,
  4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22]}}
```

### SegwitAddr

#### Encoding a SegWit program into BIP-0173 format
```elixir
iex> SegwitAddr.encode("bc", "0014751e76e8199196d454941c45d1b3a323f1433bd6")
"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
```
```elixir
iex> SegwitAddr.encode("bc", 0, [117, 30, 118, 232, 25, 145, 150, 212,
...> 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214])
"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
```

#### Decoding a BIP-0173 address into a SegWit program and formatting it as an hexadecimal ScriptPubKey
```elixir
iex> SegwitAddr.decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
{:ok, {"bc", 0, [117, 30, 118, 232, 25, 145, 150, 212,
84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214]}}
```
```elixir
iex> SegwitAddr.to_script_pub_key(0, [117, 30, 118, 232, 25, 145, 150,
...> 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214])
"0014751e76e8199196d454941c45d1b3a323f1433bd6"
```

## Development

### Running tests
```bash
$ mix deps.get
$ mix test
```

### Running static analysis

This package uses Erlang's [dialyzer](http://erlang.org/doc/man/dialyzer.html) to find software discrepancies such as definite type errors, code which has become dead or unreachable due to some programming error, unnecessary tests, etc.

```bash
$ mix deps.get
$ mix dialyzer
```
