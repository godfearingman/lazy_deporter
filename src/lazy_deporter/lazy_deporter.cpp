#include "lazy_deporter.hpp"

lazy_deporter::lazy_deporter(const std::string &entry) {
  // Load the hyperion dll into our application
  this->hyperion_module = reinterpret_cast<std::uint64_t>(LoadLibraryExA(
      "C:\\Users\\sohai\\AppData\\Local\\Roblox\\Versions\\version-"
      "2b67309334b54dab\\RobloxPlayerBeta.dll",
      nullptr, DONT_RESOLVE_DLL_REFERENCES));

  if (!this->hyperion_module) {
    std::puts("[D:] Failed to load dll");
  }
}

std::uint64_t lazy_deporter::apply_character(std::uint8_t current_char,
                                             const std::uint64_t key,
                                             const std::uint64_t multip_magic,
                                             const bool requires_upper) const {
  // Ensure lowercase character, do not encrypt as uppercase if it's a module
  // name
  if (std::isupper(current_char) && requires_upper)
    current_char = std::tolower(current_char);
  /*
  mov reg1, key
  xor reg1, reg2
  imul reg1, multip_magic
  */
  return (current_char ^ key) * multip_magic;
}

std::expected<std::uint64_t, std::string>
lazy_deporter::get_hash(const char *entry, lazy_keys keys, bool is_mod) const {
  // Create local copy of current output, at start this is defaulted to the init
  // magic
  std::uint64_t encrypted_return = keys.lazy_init_key;
  // Hyperion splits the input string into streams of two characters, so we'll
  // do the same here. We need to ensure that we get the last tuple index.
  const std::size_t len = strlen(entry),
                    tuple_len = strlen(entry) - (strlen(entry) & 1);
  // Iterate through each pair
  std::size_t idx = 0;
  while (idx != tuple_len) {
    // Encrypt first character
    encrypted_return = this->apply_character(entry[idx], encrypted_return,
                                             keys.lazy_multip, is_mod);
    // Encrypt second character
    encrypted_return = this->apply_character(entry[idx + 1], encrypted_return,
                                             keys.lazy_multip, is_mod);
    // Move onto next tuple
    idx += 2;
  }

  // Check if odd sized string, if so we need to handle the last char that was
  // left out
  if (len & 1) {
    encrypted_return = this->apply_character(entry[len - 1], encrypted_return,
                                             keys.lazy_multip, is_mod);
  }

  // Return encrypted magic to user
  return encrypted_return;
}

std::expected<std::vector<lazy_keys>, std::string>
lazy_deporter::get_all_keys() const {
  std::vector<lazy_keys> hits = {};
  std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>>
      unique_keys = {};
  // Find all hits to our original pattern
  const auto &pattern_hits =
      this->find_pattern(this->hyperion_module, this->pattern, this->mask);

  if (!pattern_hits.has_value())
    return std::unexpected(pattern_hits.error());

  for (const auto &hit : *pattern_hits) {
    // For every hit we're going to try and extract all the keys out of it
    std::uint64_t init_key_addr = hit + 19;
    std::uint64_t mod_hash = hit + 29;
    std::uint64_t multip_magic = hit + 39;

    // Create a struct out of these keys
    lazy_keys keys = {*reinterpret_cast<std::uint64_t *>(init_key_addr),
                      *reinterpret_cast<std::uint64_t *>(mod_hash),
                      *reinterpret_cast<std::uint64_t *>(multip_magic)};
    // Check if the mod hash is the equivalent of ntdll.dll or not
    const auto &hash_result = this->get_hash("ntdll.dll", keys, true);
    if (!hash_result.has_value())
      continue;

    if (*hash_result == keys.lazy_mod_hash) {
      auto key_tuple = std::make_tuple(keys.lazy_init_key, keys.lazy_mod_hash,
                                       keys.lazy_multip);
      if (unique_keys.find(key_tuple) == unique_keys.end()) {
        unique_keys.insert(key_tuple);
        hits.push_back(keys);
      }
    }
  }

  if (hits.size())
    return hits;
  return std::unexpected("Failed to find any keys");
}

std::expected<std::vector<lazy_function>, std::string>
lazy_deporter::get_all_functions() const {
  std::vector<lazy_function> hits = {};
  std::set<std::uint64_t> unique_functions = {};
  // Find all hits to our original pattern
  const auto &pattern_hits = this->find_pattern(
      this->hyperion_module, this->func_pattern, this->func_mask);

  if (!pattern_hits.has_value())
    return std::unexpected(pattern_hits.error());

  for (const auto &hit : *pattern_hits) {
    // For every hit we're going to try and extract the function hash from it,
    // this will be used later on in order to iterate through a modules' exports
    // and check the hash
    std::uint64_t function_hash = *reinterpret_cast<std::uint64_t *>(hit + 6);

    if (function_hash &&
        unique_functions.find(function_hash) == unique_functions.end()) {
      unique_functions.insert(function_hash);

      // Find out what function it was that was lazily imported here, it'll be a
      // bit ass to do but we'll need to check every single key set over all the
      // exports of ntdll
      const auto &keys = this->get_all_keys();
      if (!keys.has_value())
        return std::unexpected(keys.error());

      std::uint64_t ntdll_mod =
          reinterpret_cast<std::uint64_t>(GetModuleHandleA("ntdll.dll"));
      const auto &image_dos_header =
          reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll_mod);
      const auto &image_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
          ntdll_mod + image_dos_header->e_lfanew);

      auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(
          ntdll_mod + image_nt_header->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                          .VirtualAddress);

      auto functions =
          reinterpret_cast<DWORD *>(ntdll_mod + export_dir->AddressOfFunctions);
      auto names =
          reinterpret_cast<DWORD *>(ntdll_mod + export_dir->AddressOfNames);
      auto ordinals = reinterpret_cast<WORD *>(
          ntdll_mod + export_dir->AddressOfNameOrdinals);

      for (std::uint32_t idx = 0; idx < export_dir->NumberOfNames; idx++) {
        const char *name =
            reinterpret_cast<const char *>(ntdll_mod + names[idx]);

        // Iterate over all keys
        for (const auto &key : *keys) {
          const auto &export_hash = this->get_hash(name, key, false);
          if (!export_hash.has_value())
            continue;

          if (export_hash == function_hash) {
            // Matched, store this as an entry
            lazy_function func = {
                key,
                function_hash,
                std::string(name),
                ordinals[idx],
                functions[ordinals[idx]],
            };
            hits.push_back(func);
          }
        }
      }
    }
  }

  if (hits.size())
    return hits;
  return std::unexpected("Failed to find any keys");
}

std::expected<std::monostate, std::string>
lazy_deporter::check_mask(std::uint64_t address, const char *pattern,
                          const char *mask) const {
  for (std::size_t idx = 0; idx < strlen(mask); ++idx) {
    if (mask[idx] != '?' &&
        static_cast<unsigned char>(pattern[idx]) !=
            *reinterpret_cast<unsigned char *>(address + idx)) {
      return std::unexpected("Mismatched pattern");
    }
  }
  return std::monostate{};
}

std::expected<std::vector<uint64_t>, std::string>
lazy_deporter::find_pattern(std::uint64_t start, std::size_t size,
                            const char *pattern, const char *mask) const {
  std::vector<std::uint64_t> hits = {};
  for (std::size_t idx = 0; idx < (size - strlen(mask)); ++idx) {
    const auto &mask_check = this->check_mask(start + idx, pattern, mask);
    if (mask_check.has_value())
      hits.push_back(start + idx);
  }

  if (hits.size())
    return hits;
  return std::unexpected("Failed to find pattern");
}

std::expected<std::vector<std::uint64_t>, std::string>
lazy_deporter::find_pattern(std::uint64_t targ_module, const char *pattern,
                            const char *mask) const {
  std::vector<std::uint64_t> hits = {};
  const auto &image_dos_header =
      reinterpret_cast<PIMAGE_DOS_HEADER>(targ_module);
  const auto &image_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
      targ_module + image_dos_header->e_lfanew);

  auto curr_section = IMAGE_FIRST_SECTION(image_nt_header);
  for (int idx = 0; idx < image_nt_header->FileHeader.NumberOfSections;
       idx++, curr_section++) {
    if (!memcmp(curr_section->Name, ".byfron", 5)) {
      const auto &pattern_result =
          this->find_pattern(targ_module + curr_section->VirtualAddress,
                             curr_section->Misc.VirtualSize, pattern, mask);
      if (pattern_result.has_value())
        hits.insert(hits.end(), pattern_result->begin(), pattern_result->end());
    }
  }
  if (hits.size())
    return hits;
  return std::unexpected("Failed to find any pattern");
}
