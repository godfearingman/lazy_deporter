#include <Windows.h>
#include <expected>
#include <set>
#include <string>
#include <vector>

// Create a basic struct for storing all keys and hashes
struct lazy_keys {
  // Our init key
  std::uint64_t lazy_init_key;
  // Our ntdll.dll hash
  std::uint64_t lazy_mod_hash;
  // Our multiplier
  std::uint64_t lazy_multip;
};

// Create a basic struct for storing any information regarding lazily imported
// functions
struct lazy_function {
  // Our parent key struct
  lazy_keys lazy_key;
  // Our function hash
  std::uint64_t lazy_hash;
  // Our matched string name of the function
  std::string lazy_name;
  // Our matched function's ordinal value
  std::uint16_t lazy_ordinal;
  // Our matched function's rva
  std::uint32_t lazy_rva;
  // Our matched function's obfuscated address
  // std::uint64_t lazy_obfuscated;
};

class lazy_deporter {
private:
  std::uint64_t hyperion_module;

public:
  // Basic constructor
  lazy_deporter(const std::string &mod);
  // Gets hash of an input string which should be a module
  std::expected<std::uint64_t, std::string>
  get_hash(const char *entry, lazy_keys keys, bool is_mod) const;

  std::expected<std::vector<lazy_keys>, std::string> get_all_keys() const;

  // The interesting part about the actual function calls is that it has some
  // sort of RNG table used for obfuscating the api address, when it comes to
  // calling it - it will deobfuscate the api address immediately after it has
  // obfuscated it - there's a high chance that it will always be different too
  // due to the RNG table. Albeit in static reversal, it's not really anything
  // special to look into because we can see it just fine being obfuscated and
  // deobfuscated.
  std::expected<std::vector<lazy_function>, std::string>
  get_all_functions() const;

private:
  // Apply encryption algorithm to single character
  std::uint64_t apply_character(std::uint8_t current_char,
                                const std::uint64_t key,
                                const std::uint64_t multip_magic,
                                const bool requires_upper) const;

private:
  // Essentially, after almost every reference to these instructions, the lazy
  // importer keys are exposed right after. These instructions are to do with
  // getting the loaded moules list per PEB
  /*
  mov rcx, gs:0x60
  mov rcx, [rcx+0x18]
  add rcx, 0x10
  */
  constexpr static const char *pattern =
      "\x65\x00\x00\x00\x25\x60\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x10";
  constexpr static const char *mask = "x???xxxxx???x???x";

  // When it comes to getting function hashes, it's almost the exact same as
  // getting module hashes but we don't uppercase it
  constexpr static const char *func_pattern =
      "\x49\x0F\xAF\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x39\x00";
  constexpr static const char *func_mask = "xxx?x?????????xx?";

private:
  // Pattern scanning related functions
  std::expected<std::monostate, std::string> check_mask(std::uint64_t address,
                                                        const char *pattern,
                                                        const char *mask) const;

  std::expected<std::vector<uint64_t>, std::string>
  find_pattern(std::uint64_t start, std::size_t size, const char *pattern,
               const char *mask) const;

  std::expected<std::vector<std::uint64_t>, std::string>
  find_pattern(std::uint64_t targ_module, const char *pattern,
               const char *mask) const;
};
