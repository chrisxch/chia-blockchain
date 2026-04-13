from __future__ import annotations

import logging
from collections.abc import Awaitable
from typing import Any

import pytest
from chia_rs import CoinRecord, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64

from chia.full_node.xkv8_miner import Xkv8MinerService, Xkv8PeakEvent, Xkv8SpendBundleBuilder
from chia.types.blockchain_format.coin import Coin
from chia.types.mempool_inclusion_status import MempoolInclusionStatus

MINER_SECRET_KEY = "5837151d0ab79dfdd7a9e8d323b7fb5b9862f5e115a47d100567e5dfea05bb30"  # noqa: S105
TARGET_ADDRESS = "xch18yemnah6vgrx6k8cl9q4pk3t5jgk9808a530jh0hc7nfz5qqk2dqrkfle8"
GENESIS_CHALLENGE = bytes32.from_hexstr("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")


class FakeCoinStore:
    def __init__(self, records: list[CoinRecord], parent_record: CoinRecord) -> None:
        self.records = records
        self.parent_record = parent_record

    async def get_coin_records_by_puzzle_hash(self, *args: object) -> list[CoinRecord]:
        return self.records

    async def get_coin_record(self, coin_id: bytes32) -> CoinRecord | None:
        if coin_id == self.parent_record.coin.name():
            return self.parent_record
        return None


def test_xkv8_builder_matches_standalone_hashes() -> None:
    builder = Xkv8SpendBundleBuilder(MINER_SECRET_KEY, TARGET_ADDRESS, GENESIS_CHALLENGE)

    assert builder.inner_puzzle_hash.hex() == "5cabf8127d062d8e68c74dffc0cfd6522e2e5298c5999122fde78de4d06d0d5c"
    assert builder.full_cat_puzzlehash.hex() == "e758f3dba6baac1a6e581ce46537811157621986e18c350075948049abc479f1"
    assert builder.eph_inner_ph.hex() == "50c07c162fc4bfa38a3d6bf2d308fab168b67e18d271beb0a9c7c094511c362c"


@pytest.mark.anyio
async def test_xkv8_miner_cold_start_builds_and_submits_bundle() -> None:
    submitted: list[tuple[bytes32, SpendBundle]] = []

    async def add_transaction(bundle: SpendBundle, spend_name: bytes32) -> tuple[MempoolInclusionStatus, Any]:
        submitted.append((spend_name, bundle))
        return MempoolInclusionStatus.PENDING, None

    service = Xkv8MinerService(
        config={
            "miner_secret_key": MINER_SECRET_KEY,
            "target_address": TARGET_ADDRESS,
            "target_depth": 1,
        },
        coin_store=None,
        add_transaction=add_transaction,
        genesis_challenge=GENESIS_CHALLENGE,
        logger=logging.getLogger(__name__),
    )

    parent_coin = Coin(bytes32.from_hexstr("11" * 32), service.builder.full_cat_puzzlehash, uint64(21_000_000_000))
    lode_coin = Coin(parent_coin.name(), service.builder.full_cat_puzzlehash, uint64(20_999_990_000))
    parent_record = CoinRecord(parent_coin, uint32(8521888), uint32(8521889), False, uint64(0))
    lode_record = CoinRecord(lode_coin, uint32(8521889), uint32(0), False, uint64(0))
    service.coin_store = FakeCoinStore([lode_record], parent_record)

    async def get_known_nonce(target_height: int) -> int | None:
        assert target_height == 8521890
        return 2550875531

    service._get_nonce = get_known_nonce  # type: ignore[method-assign]

    await service._handle_peak(
        Xkv8PeakEvent(
            height=uint32(8521889),
            tx_height=uint32(8521889),
            header_hash=bytes32.from_hexstr("22" * 32),
            fork_height=uint32(8521888),
            is_transaction_block=True,
            removals=[],
            additions=[],
        )
    )

    await _await_build_tasks(service._build_tasks)

    assert len(submitted) == 1
    assert submitted[0][0] == submitted[0][1].name()
    assert (lode_coin.name(), 8521890) in service._submitted


async def _await_build_tasks(tasks: dict[tuple[bytes32, int], Awaitable[None]]) -> None:
    for task in list(tasks.values()):
        await task
