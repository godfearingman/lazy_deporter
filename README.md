# Lazy Deporter

A C++ tool to analyse and dump the lazily imported functions from Hyperion

## Overview

Attempt to find all keysets within Hyperion's dll and use to dump any found function hashes within the DLL to named functions.

## Features

- Identify and extract all lazy import key sets
- Resolves function hashes to their actual function names
- Provides the ability to dump all lazily imported functions with their metadata

## Writeup
https://x64.gg/t/reversing-a-lazy-importer/93

## Use
Change https://github.com/godfearingman/lazy_deporter/blob/main/src/lazy_deporter/lazy_deporter.cpp#L5 to the path of your hyperion dll
