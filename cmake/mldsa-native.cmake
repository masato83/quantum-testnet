# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

enable_language(C)

function(add_mldsa_native subdir)
  message("")
  message("Configuring mldsa-native subtree...")

  add_library(mldsa_native STATIC
    ${subdir}/mldsa/mldsa_native.c
  )

  target_include_directories(mldsa_native
    PUBLIC
      ${subdir}/mldsa
  )

  target_compile_definitions(mldsa_native
    PUBLIC
      MLD_CONFIG_PARAMETER_SET=87
      MLD_CONFIG_NO_RANDOMIZED_API
  )

  set_target_properties(mldsa_native PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endfunction()
