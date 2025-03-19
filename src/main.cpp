#include "lazy_deporter/lazy_deporter.hpp"
#include <Windows.h>

int main() {

  lazy_deporter test = lazy_deporter("ntdll.dll");
  auto keys = test.get_all_keys();
  if (!keys.has_value()) {
    std::printf("[D:] %s\n", keys.error().c_str());
    system("pause");
    return 0;
  }

  for (const auto &key : *keys) {
    std::printf("[:D] got hit\n\t->init key = %llx\n\t->multiply magic = "
                "%llx\n\t->ntdll hash = %llx\n",
                key.lazy_init_key, key.lazy_multip, key.lazy_mod_hash);
  }
  std::puts("");

  auto functions = test.get_all_functions();
  if (!functions.has_value()) {
    std::printf("[D:] %s\n", keys.error().c_str());
    system("pause");
    return 0;
  }
  for (const auto &function : *functions) {
    std::printf("[:D] got hit\n\t->function hash = %llx\n\t->function name = "
                "%s\n\t->function ordinal = %x\n\t->function rva = %I32x\n",
                function.lazy_hash, function.lazy_name.c_str(),
                function.lazy_ordinal, function.lazy_rva);
  }

  system("pause");
  return 0;
}
