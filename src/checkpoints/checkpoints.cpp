// Copyright (c) 2014-2023, The Monero Project
// Copyright (c)      2023, The Oxen Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_core/rules.h"
#include <vector>
#include "syncobj.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace epee;

#include "common/sispop_integration_test_hooks.h"
#include "common/sispop.h"

#undef SISPOP_DEFAULT_LOG_CATEGORY
#define SISPOP_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  bool checkpoint_t::check(crypto::hash const &hash) const
  {
    bool result = block_hash == hash;
    if (result) MINFO   ("CHECKPOINT PASSED FOR HEIGHT " << height << " " << block_hash);
    else        MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH " << block_hash << "GIVEN HASH: " << hash);
    return result;
  }

  //---------------------------------------------------------------------------
  const std::map<uint64_t,  difficulty_type>& checkpoints::get_difficulty_points() const
  {
    return m_difficulty_points;
  }

  height_to_hash const HARDCODED_MAINNET_CHECKPOINTS[] =
  {
    {0,      "8cc33ab439f5fec5a384321b872c25686d2ab9d688e715ee3087b20094fccd47", "0x1"     },
    {10,     "341bfd95900a0cf2fbf5e3244fc82ad9f3bdd22c6a96badc25c14ef7dcf4c997", "0xfde"   },
    {20,     "903550d15890ea3384c5836417f99ad23989c98fb646f62aa2376a7939a6e1a2", "0x2555"  },
    {30,     "571c2b3e2aeac685557ad0be03ab82b97d760be3220bed01ae4c999008000983", "0x44aa"  },
    {40,     "ae944e594586af0a892881912be0d25a19419de0c727a4104a443715d8d0b47a", "0x682b"  },
    {50,     "0b5007e09ad0db09556a9e691e396c2fcaa095d8a4510d2d037f0978a045b684", "0x8aed"  },
    {60,     "b7532566f52330faa9560e6af7df3a394297847e9bc031d09bfa677208a374fe", "0xaeb6"  },
    {70,     "18bb4dfd98e703b714de4f885a829edd524d36a909386ab8ed51895deb7b8fba", "0xd37a"  },
    {80,     "6f307e7fbe359ceae0b648090b82f1e34c74516a6a254a5be9fb6517fd00df8b", "0xfa46"  },
    {90,     "4e2c84c95171bea9c0d0a53b59b97ff08280050e2dd8a1c6c797cf102da82d6a", "0x124fa" },
    {100,    "d3ab9f7bcea8fd3f6b182e1d856e392f0a1e8630e2a8ce5566969c13e76a59e5", "0x1528f" },
    {110,    "0d76813f0d8d6cc397e1cc64a6c2ce5c22b583d5b629c7aa40ad6378a5bb19ec", "0x184a3" },
    {120,    "eda28bd557ebe6172b9aa3a9cc0a0155c3b232bd1b5afd85c2ecf1c2377b3b1e", "0x1ba16" },
    {130,    "20f9c812877a1a31375ebec3b7c4fef7bce44857ae4769333d8c3ab85024a68a", "0x1f151" },
    {140,    "378352fb3e0cad6445a5db314a1a6de018191b146a0cd14058a338339be69928", "0x22728" },
    {150,    "ddc79a169597bfb90fc560b5e700d817f2d887536cc61781bc3ecfd2f1cb8b83", "0x25dcb" },
    {160,    "a9d00e625af966995c305c3ecc1ea859855ff323d2b29963676742138aff323a", "0x29495" },
    {170,    "35e7110b4712461d110cf2a8415adf0d76b012faa50b7131f401a1d23075f6c6", "0x2cf32" },
    {180,    "b7b4edca01bd9cb657c3e1d2b703a1c936a3e122a00917142c7669b438898c76", "0x30dde" },
    {190,    "725a3597e4e2c231f8fecf0ffdcabd1d3134cbd80eb02dfb2c02456f438ba73f", "0x350a5" },
    {200,    "14cc754b636d7fd90dc65398d399c9e312dc0b2a1bacb61404f4cd3695c7ad4f", "0x394b1" },
    {210,    "b38970ce0157b5b63957aad3083ddd1af1eed8b23fee4f2ede86683a62937304", "0x3d9b8" },
    {220,    "54bd35d7b98831a56f48575930d4a3a3c2560c463f4e5a5b2184e4fcd40f959d", "0x41ea7" },
    {230,    "fb0d96fa6be43b344a779664f7ad1ac34c2c9842cdc6fe6c0496a380ed8e8137", "0x466da" },
    {240,    "c08a534f3acd3a8f3a3fe422f3bc8c0a6eed927540c44d5c03edde642eef5640", "0x4abbb" },
    {250,    "724c72dcdcda195445372307cfceef8f17303e5ff95ddc8790b5cebb4f2dad0e", "0x4f068" },
    {260,    "f8490d4c787a7309568eb767c777918fa464a0ef25e3748c40e135154e97e796", "0x5353f" },
    {270,    "0b1c9e495708ea56922158023ab9e7815cbd8eb379b9ff084faa6f5565d504cc", "0x58081" },
    {280,    "5c40092e5dafb98321316573544a99358f9d958e04bfa169fe63a7b07b507ae2", "0x5b8b1" },
    {290,    "d7a3521da5886e0218b683cef7472ff9aab7891876f3e0c9f8b0a07dd53fb481", "0x5ed41" },
    {300,    "c0a522a2580dc105e47fcd2568cf085ec899a4d9ef43cca94752a0d25765c2f0", "0x62832" },
    {310,    "9cc4c1526701790ed9dddf980bcb288ca753f8777e274a738842df383560c930", "0x669fa" },
    {320,    "bff91a18e55d6fefe9a980811d43efd1b0ec268b41fe38ddcfc12da53406ebe1", "0x6ad94" },
  };

  height_to_hash const HARDCODED_TESTNET_CHECKPOINTS[] =
  {
    {127028, "83f6ea8d62601733a257d2f075fd960edd80886dc090d8751478c0a738caa09e"},
  };

  crypto::hash get_newest_hardcoded_checkpoint(cryptonote::network_type nettype, uint64_t *height)
  {
    crypto::hash result = crypto::null_hash;
    *height = 0;
    if (nettype != MAINNET && nettype != TESTNET)
      return result;

    if (nettype == MAINNET)
    {
      uint64_t last_index         = sispop::array_count(HARDCODED_MAINNET_CHECKPOINTS) - 1;
      height_to_hash const &entry = HARDCODED_MAINNET_CHECKPOINTS[last_index];

      if (epee::string_tools::hex_to_pod(entry.hash, result))
        *height = entry.height;
    }
    else
    {
      uint64_t last_index         = sispop::array_count(HARDCODED_TESTNET_CHECKPOINTS) - 1;
      height_to_hash const &entry = HARDCODED_TESTNET_CHECKPOINTS[last_index];

      if (epee::string_tools::hex_to_pod(entry.hash, result))
        *height = entry.height;
    }

    return result;
  }

  bool load_checkpoints_from_json(const std::string &json_hashfile_fullpath, std::vector<height_to_hash> &checkpoint_hashes)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    height_to_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }

    checkpoint_hashes = std::move(hashes.hashlines);
    return true;
  }

  bool checkpoints::get_checkpoint(uint64_t height, checkpoint_t &checkpoint) const
  {
    try
    {
      auto guard = db_rtxn_guard(m_db);
      return m_db->get_block_checkpoint(height, checkpoint);
    }
    catch (const std::exception &e)
    {
      MERROR("Get block checkpoint from DB failed at height: " << height << ", what = " << e.what());
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str, const std::string& difficulty_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r         = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    checkpoint_t checkpoint = {};
    if (get_checkpoint(height, checkpoint))
    {
      crypto::hash const &curr_hash = checkpoint.block_hash;
      CHECK_AND_ASSERT_MES(h == curr_hash, false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    else
    {
      checkpoint.type       = checkpoint_type::hardcoded;
      checkpoint.height     = height;
      checkpoint.block_hash = h;
      r                     = update_checkpoint(checkpoint);
    }
    return r;
  }
  bool checkpoints::update_checkpoint(checkpoint_t const &checkpoint)
  {
    // NOTE(sispop): Assumes checkpoint is valid
    bool result        = true;
    bool batch_started = false;
    try
    {
      batch_started = m_db->batch_start();
      m_db->update_block_checkpoint(checkpoint);
    }
    catch (const std::exception& e)
    {
      MERROR("Failed to add checkpoint with hash: " << checkpoint.block_hash << " at height: " << checkpoint.height << ", what = " << e.what());
      result = false;
    }

    if (batch_started)
      m_db->batch_stop();
    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, checkpoint_t const *checkpoint)
  {
    uint64_t const height = get_block_height(block);
    if (height < masternodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL || block.major_version < network_version_12)
      return true;

    uint64_t end_cull_height = 0;
    {
      checkpoint_t immutable_checkpoint;
      if (m_db->get_immutable_checkpoint(&immutable_checkpoint, height + 1))
        end_cull_height = immutable_checkpoint.height;
    }
    uint64_t start_cull_height = (end_cull_height < masternodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL)
                                     ? 0
                                     : end_cull_height - masternodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;

    if ((start_cull_height % masternodes::CHECKPOINT_INTERVAL) > 0)
      start_cull_height += (masternodes::CHECKPOINT_INTERVAL - (start_cull_height % masternodes::CHECKPOINT_INTERVAL));

    m_last_cull_height = std::max(m_last_cull_height, start_cull_height);
    auto guard         = db_wtxn_guard(m_db);
    for (; m_last_cull_height < end_cull_height; m_last_cull_height += masternodes::CHECKPOINT_INTERVAL)
    {
      if (m_last_cull_height % masternodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
        continue;

      try
      {
        m_db->remove_block_checkpoint(m_last_cull_height);
      }
      catch (const std::exception &e)
      {
        MERROR("Pruning block checkpoint on block added failed non-trivially at height: " << m_last_cull_height << ", what = " << e.what());
      }
    }

    if (checkpoint)
        update_checkpoint(*checkpoint);

    return true;
  }
  //---------------------------------------------------------------------------
  void checkpoints::blockchain_detached(uint64_t height)
  {
    m_last_cull_height = std::min(m_last_cull_height, height);

    checkpoint_t top_checkpoint;
    auto guard = db_wtxn_guard(m_db);
    if (m_db->get_top_checkpoint(top_checkpoint))
    {
      uint64_t start_height = top_checkpoint.height;
      for (size_t delete_height = start_height;
           delete_height >= height && delete_height >= masternodes::CHECKPOINT_INTERVAL;
           delete_height -= masternodes::CHECKPOINT_INTERVAL)
      {
        try
        {
          m_db->remove_block_checkpoint(delete_height);
        }
        catch (const std::exception &e)
        {
          MERROR("Remove block checkpoint on detach failed non-trivially at height: " << delete_height << ", what = " << e.what());
        }
      }
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    uint64_t top_checkpoint_height = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      top_checkpoint_height = top_checkpoint.height;

    return height <= top_checkpoint_height;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool* is_a_checkpoint, bool *masternode_checkpoint) const
  {
    checkpoint_t checkpoint;
    bool found = get_checkpoint(height, checkpoint);
    if (is_a_checkpoint) *is_a_checkpoint = found;
    if (masternode_checkpoint) *masternode_checkpoint = false;

    if(!found)
      return true;

    bool result = checkpoint.check(h);
    if (masternode_checkpoint)
      *masternode_checkpoint = (checkpoint.type == checkpoint_type::masternode);

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height, bool *masternode_checkpoint)
  {
    if (masternode_checkpoint)
      *masternode_checkpoint = false;

    if (0 == block_height)
      return false;

    {
      std::vector<checkpoint_t> const first_checkpoint = m_db->get_checkpoints_range(0, blockchain_height, 1);
      if (first_checkpoint.empty() || blockchain_height < first_checkpoint[0].height)
        return true;
    }

    checkpoint_t immutable_checkpoint;
    uint64_t immutable_height = 0;
    if (m_db->get_immutable_checkpoint(&immutable_checkpoint, blockchain_height))
    {
      immutable_height = immutable_checkpoint.height;
      if (masternode_checkpoint)
        *masternode_checkpoint = (immutable_checkpoint.type == checkpoint_type::masternode);
    }

    m_immutable_height = std::max(immutable_height, m_immutable_height);
    bool result        = block_height > m_immutable_height;
    return result;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    uint64_t result = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      result = top_checkpoint.height;

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::init(network_type nettype, struct BlockchainDB *db)
  {
    *this     = {};
    m_db      = db;
    m_nettype = nettype;

#if !defined(SISPOP_ENABLE_INTEGRATION_TEST_HOOKS)
    if (nettype == MAINNET)
    {
      for (size_t i = 0; i < sispop::array_count(HARDCODED_MAINNET_CHECKPOINTS); ++i)
      {
        height_to_hash const &checkpoint = HARDCODED_MAINNET_CHECKPOINTS[i];
        ADD_CHECKPOINT(checkpoint.height, checkpoint.hash, checkpoint.difficulty);
      }
    }
    else if (nettype == TESTNET)
    {
      for (size_t i = 0; i < sispop::array_count(HARDCODED_TESTNET_CHECKPOINTS); ++i)
      {
        height_to_hash const &checkpoint = HARDCODED_TESTNET_CHECKPOINTS[i];
        ADD_CHECKPOINT(checkpoint.height, checkpoint.hash, checkpoint.difficulty);
      }
    }
#endif

    return true;
  }

}

