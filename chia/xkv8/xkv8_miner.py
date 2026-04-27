from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import os
import random
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from functools import partial
from typing import Any

from chia_rs import AugSchemeMPL, CoinRecord, PrivateKey, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.util.bech32m import decode_puzzle_hash
from chia.util.task_referencer import create_referenced_task
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    CAT_MOD_HASH_HASH,
    QUOTED_CAT_MOD_HASH,
    SpendableCAT,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.derive_keys import master_sk_to_wallet_sk_unhardened
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles import p2_delegated_puzzle_or_hidden_puzzle
from chia.wallet.puzzles.p2_conditions import puzzle_for_conditions
from chia.wallet.util.curry_and_treehash import curry_and_treehash, shatree_atom
from chia.wallet.wallet_spend_bundle import WalletSpendBundle

log = logging.getLogger(__name__)

CAT_TAIL_HASH = bytes32.from_hexstr("f09c8d630a0a64eb4633c0933e0ca131e646cebb384cfc4f6718bad80859b5e8")
GENESIS_HEIGHT = 8521888
EPOCH_LENGTH = 1_120_000
BASE_REWARD = 10_000
BASE_DIFFICULTY = 2**238

PUZZLE_HEX = (
    "ff02ffff01ff02ff7effff04ff02ffff04ff8202ffffff04ffff02ff52ffff04ff02ffff04"
    "ff0bffff04ff17ffff04ff8205ffff808080808080ffff04ff8205ffffff04ff820bffffff"
    "04ff2fffff04ff8217ffffff04ff822fffffff04ff825fffffff04ffff02ff56ffff04ff02"
    "ffff04ff81bfffff04ffff02ff26ffff04ff02ffff04ff820bffffff04ff2fffff04ff5fff"
    "808080808080ff8080808080ffff04ffff02ff7affff04ff02ffff04ff82017fffff04ffff"
    "02ff26ffff04ff02ffff04ff820bffffff04ff2fffff04ff5fff808080808080ff80808080"
    "80ff80808080808080808080808080ffff04ffff01ffffffff3257ff53ff5249ffff48ff33"
    "3cff01ff0102ffffffff02ffff03ff05ffff01ff0bff8201f2ffff02ff76ffff04ff02ffff"
    "04ff09ffff04ffff02ff22ffff04ff02ffff04ff0dff80808080ff808080808080ffff0182"
    "01b280ff0180ffff02ff2affff04ff02ffff04ff05ffff04ffff02ff5effff04ff02ffff04"
    "ff05ff80808080ffff04ffff02ff5effff04ff02ffff04ff0bff80808080ffff04ff17ff80"
    "808080808080ffffa04bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce2"
    "3c7785459aa09dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718b"
    "a7b2ffa102a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f6322"
    "2a102a8d5dd63fba471ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5fff"
    "f0bff820172ffff02ff76ffff04ff02ffff04ff05ffff04ffff02ff22ffff04ff02ffff04"
    "ff07ff80808080ff808080808080ffff04ffff04ff78ffff04ff05ff808080ffff04ffff04"
    "ff24ffff04ff0bff808080ffff04ffff04ff58ffff01ff018080ffff04ffff04ff28ffff04"
    "ff2fff808080ffff04ffff04ff30ffff04ffff10ff2fffff010380ff808080ffff04ffff04"
    "ff20ffff04ff5fffff04ffff0bff81bfff82017fff2f80ff80808080ffff04ffff04ff5cff"
    "ff04ff5fff808080ffff04ffff04ff54ffff04ff81bfffff04ff8202ffffff04ffff04ff81"
    "bfff8080ff8080808080ffff04ffff04ff54ffff04ff17ffff04ffff11ff05ff8202ff80ff"
    "ff04ffff04ff17ff8080ff8080808080ffff04ffff04ff74ffff01ff248080ff8080808080"
    "808080808080ff16ff05ffff11ff80ff0b8080ffffff02ffff03ffff15ffff05ffff14ffff"
    "11ff05ff0b80ff178080ffff010380ffff01ff0103ffff01ff05ffff14ffff11ff05ff0b80"
    "ff17808080ff0180ffff16ff05ffff11ff80ff0b8080ff0bff7cffff0bff7cff8201b2ff05"
    "80ffff0bff7cff0bff8201328080ffff02ffff03ffff15ff05ff8080ffff01ff15ff0bff05"
    "80ff8080ff0180ffff02ffff03ffff07ff0580ffff01ff0bff7cffff02ff5effff04ff02ff"
    "ff04ff09ff80808080ffff02ff5effff04ff02ffff04ff0dff8080808080ffff01ff0bff2c"
    "ff058080ff0180ff02ffff03ffff15ff2fff5f80ffff01ff02ffff03ffff02ff2effff04ff"
    "02ffff04ffff0bff17ff81bfff2fff8202ff80ffff04ff820bffff8080808080ffff01ff02"
    "ffff03ffff20ffff15ff8205ffff058080ffff01ff02ff5affff04ff02ffff04ff05ffff04"
    "ff0bffff04ff17ffff04ff2fffff04ff81bfffff04ff82017fffff04ff8202ffffff04ff82"
    "05ffff8080808080808080808080ffff01ff088080ff0180ffff01ff088080ff0180ffff01"
    "ff088080ff0180ff018080"
)

NUM_WORKERS = max(1, os.cpu_count() or 4)
_pow_pool: ProcessPoolExecutor | None = None


def _get_pow_pool() -> ProcessPoolExecutor:
    global _pow_pool
    if _pow_pool is None:
        _pow_pool = ProcessPoolExecutor(max_workers=NUM_WORKERS)
    return _pow_pool


def _reset_pow_pool() -> None:
    global _pow_pool
    if _pow_pool is not None:
        try:
            _pow_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        _pow_pool = None


def int_to_clvm_bytes(n: int) -> bytes:
    if n == 0:
        return b""
    byte_len = (n.bit_length() + 8) // 8
    return n.to_bytes(byte_len, "big", signed=True)


def pow_sha256(*args: bytes | int) -> bytes:
    h = hashlib.sha256()
    for arg in args:
        h.update(int_to_clvm_bytes(arg) if isinstance(arg, int) else arg)
    return h.digest()


def get_epoch(user_height: int) -> int:
    raw = (user_height - GENESIS_HEIGHT) // EPOCH_LENGTH
    return min(raw, 3)


def get_reward(epoch: int) -> int:
    return BASE_REWARD >> epoch


def get_difficulty(epoch: int) -> int:
    return BASE_DIFFICULTY >> epoch


def full_cat_puzzle_hash(inner_puzzle_hash: bytes32) -> bytes32:
    return curry_and_treehash(
        QUOTED_CAT_MOD_HASH,
        CAT_MOD_HASH_HASH,
        shatree_atom(CAT_TAIL_HASH),
        inner_puzzle_hash,
    )


def _grind_nonce_range(
    inner_puzzle_hash: bytes,
    miner_pubkey_bytes: bytes,
    h_bytes: bytes,
    difficulty: int,
    start: int,
    count: int,
) -> int | None:
    for nonce in range(start, start + count):
        digest = hashlib.sha256(
            inner_puzzle_hash + miner_pubkey_bytes + h_bytes + int_to_clvm_bytes(nonce)
        ).digest()
        pow_int = int.from_bytes(digest, "big")
        if pow_int > 0 and difficulty > pow_int:
            return nonce
    return None


def find_valid_nonce(
    inner_puzzle_hash: bytes,
    miner_pubkey_bytes: bytes,
    user_height: int,
    difficulty: int,
    max_attempts: int = 5_000_000,
) -> int | None:
    h_bytes = int_to_clvm_bytes(user_height)
    chunk = max(1, max_attempts // NUM_WORKERS)
    # If a worker process dies, ProcessPoolExecutor enters a BrokenProcessPool
    # state and every subsequent submit/result call raises. Recreate the pool
    # and retry once so transient worker death doesn't permanently halt mining.
    for attempt in range(2):
        pool = _get_pow_pool()
        futures: list[Future[int | None]] = []
        try:
            for _ in range(NUM_WORKERS):
                futures.append(
                    pool.submit(
                        _grind_nonce_range,
                        inner_puzzle_hash,
                        miner_pubkey_bytes,
                        h_bytes,
                        difficulty,
                        random.randint(0, 2**32),
                        chunk,
                    )
                )
            for future in as_completed(futures):
                nonce = future.result()
                if nonce is not None:
                    return nonce
            return None
        except BrokenProcessPool:
            log.warning("XKV8 nonce search: ProcessPool broken, resetting (attempt %d)", attempt + 1)
            _reset_pow_pool()
        finally:
            for future in futures:
                future.cancel()
    return None


@dataclasses.dataclass(frozen=True)
class Xkv8PeakEvent:
    height: uint32
    tx_height: uint32
    header_hash: bytes32
    fork_height: uint32
    is_transaction_block: bool
    removals: list[tuple[bytes32, bytes32]]
    additions: list[tuple[Coin, bytes | None]]


@dataclasses.dataclass
class CachedBundle:
    target_height: int
    lode_coin_id: bytes32
    bundle: SpendBundle


class Xkv8SpendBundleBuilder:
    def __init__(self, miner_secret_key: str, target_address: str, genesis_challenge: bytes32) -> None:
        sk_bytes = bytes.fromhex(miner_secret_key.removeprefix("0x"))
        try:
            master_sk = PrivateKey.from_bytes(sk_bytes)
        except ValueError:
            master_sk = AugSchemeMPL.key_gen(sk_bytes)
        self.sk = master_sk_to_wallet_sk_unhardened(master_sk, uint32(0))
        self.pk = self.sk.get_g1()
        self.pk_bytes = bytes(self.pk)
        self.synthetic_sk = p2_delegated_puzzle_or_hidden_puzzle.calculate_synthetic_secret_key(
            self.sk, p2_delegated_puzzle_or_hidden_puzzle.DEFAULT_HIDDEN_PUZZLE_HASH
        )
        self.synthetic_pk = self.synthetic_sk.get_g1()
        self.eph_inner_puzzle = p2_delegated_puzzle_or_hidden_puzzle.puzzle_for_pk(self.pk)
        self.eph_inner_ph = self.eph_inner_puzzle.get_tree_hash()
        self.target_puzzlehash = decode_puzzle_hash(target_address)
        self.genesis_challenge = genesis_challenge

        mod = Program.from_bytes(bytes.fromhex(PUZZLE_HEX))
        self.inner_puzzle = mod.curry(
            mod.get_tree_hash(),
            CAT_MOD.get_tree_hash(),
            CAT_TAIL_HASH,
            GENESIS_HEIGHT,
            EPOCH_LENGTH,
            BASE_REWARD,
            BASE_DIFFICULTY,
        )
        self.inner_puzzle_hash = self.inner_puzzle.get_tree_hash()
        self.full_cat_puzzlehash = full_cat_puzzle_hash(self.inner_puzzle_hash)
        self.eph_full_cat_puzzlehash = full_cat_puzzle_hash(self.eph_inner_ph)

        self._lineage_proof: LineageProof | None = None
        self._lineage_coin_record: CoinRecord | None = None

    def set_lineage(self, lode_cr: CoinRecord, lineage_proof: LineageProof) -> None:
        self._lineage_proof = lineage_proof
        self._lineage_coin_record = lode_cr

    def _advance_lineage(self, lode_cr: CoinRecord) -> bool:
        current = self._lineage_coin_record
        if self._lineage_proof is None or current is None:
            return False

        if lode_cr.coin.name() == current.coin.name():
            return True

        if lode_cr.coin.parent_coin_info == current.coin.name():
            self._lineage_proof = LineageProof(
                current.coin.parent_coin_info,
                self.inner_puzzle_hash,
                uint64(current.coin.amount),
            )
            self._lineage_coin_record = lode_cr
            return True

        return False

    def _lode_inner_solution(self, amount: int, target_height: int, nonce: int) -> Program:
        return Program.to(
            [
                amount,
                self.inner_puzzle_hash,
                target_height,
                self.pk_bytes,
                self.eph_inner_ph,
                nonce,
            ]
        )

    def build(self, lode_cr: CoinRecord, target_height: int, nonce: int) -> SpendBundle:
        if not self._advance_lineage(lode_cr):
            raise ValueError("XKV8 lode CAT lineage is not available")
        assert self._lineage_proof is not None

        reward = get_reward(get_epoch(target_height))
        if lode_cr.coin.amount < reward:
            raise ValueError(f"XKV8 lode coin amount {lode_cr.coin.amount} is less than reward {reward}")

        lode_inner_solution = self._lode_inner_solution(lode_cr.coin.amount, target_height, nonce)
        lode_cat = SpendableCAT(
            lode_cr.coin,
            CAT_TAIL_HASH,
            self.inner_puzzle,
            lode_inner_solution,
            lineage_proof=self._lineage_proof,
        )

        eph_coin = Coin(lode_cr.coin.name(), self.eph_full_cat_puzzlehash, uint64(reward))
        eph_conditions = Program.to([
            [ConditionOpcode.CREATE_COIN, self.target_puzzlehash, reward],
            [ConditionOpcode.ASSERT_EPHEMERAL],
        ])
        eph_delegated_puzzle = puzzle_for_conditions(eph_conditions)
        eph_inner_solution = p2_delegated_puzzle_or_hidden_puzzle.solution_for_delegated_puzzle(
            eph_delegated_puzzle, Program.to(0)
        )
        eph_cat = SpendableCAT(
            eph_coin,
            CAT_TAIL_HASH,
            self.eph_inner_puzzle,
            eph_inner_solution,
            lineage_proof=LineageProof(
                lode_cr.coin.parent_coin_info,
                self.inner_puzzle_hash,
                uint64(lode_cr.coin.amount),
            ),
        )

        unsigned = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [lode_cat, eph_cat])
        mining_msg = pow_sha256(self.eph_inner_ph, nonce, target_height) + lode_cr.coin.name() + self.genesis_challenge
        eph_msg = eph_delegated_puzzle.get_tree_hash() + eph_coin.name() + self.genesis_challenge
        signature = AugSchemeMPL.aggregate(
            [
                AugSchemeMPL.sign(self.sk, mining_msg),
                AugSchemeMPL.sign(self.synthetic_sk, eph_msg),
            ]
        )
        return WalletSpendBundle(unsigned.coin_spends, signature)


class Xkv8MinerService:
    def __init__(
        self,
        *,
        config: dict[str, Any],
        coin_store: Any,
        add_transaction: Callable[[SpendBundle, bytes32], Awaitable[tuple[MempoolInclusionStatus, Any]]],
        genesis_challenge: bytes32,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.coin_store = coin_store
        self.add_transaction = add_transaction
        self.log = logger
        self.target_depth = min(max(1, int(config.get("target_depth", 2))), 4)
        self.builder = Xkv8SpendBundleBuilder(
            str(config["miner_secret_key"]),
            str(config["target_address"]),
            genesis_challenge,
        )

        self._queue: asyncio.Queue[Xkv8PeakEvent] = asyncio.Queue(maxsize=32)
        self._worker_task: asyncio.Task[None] | None = None
        self._build_tasks: dict[tuple[bytes32, int], asyncio.Task[None]] = {}
        self._nonce_tasks: dict[int, asyncio.Task[int | None]] = {}
        self._nonce_cache: dict[int, int] = {}
        self._nonce_semaphore = asyncio.Semaphore(1)
        self._cached_unspent_crs: dict[bytes32, CoinRecord] | None = None
        self._lode_state_dirty = True
        self._last_lode_cr: CoinRecord | None = None
        self._bundles: dict[tuple[bytes32, int], CachedBundle] = {}
        self._submitted: set[tuple[bytes32, int]] = set()

    @classmethod
    def create_if_enabled(
        cls,
        *,
        config: dict[str, Any],
        coin_store: Any,
        add_transaction: Callable[[SpendBundle, bytes32], Awaitable[tuple[MempoolInclusionStatus, Any]]],
        genesis_challenge: bytes32,
        logger: logging.Logger,
    ) -> Xkv8MinerService | None:
        miner_config = config.get("xkv8_miner", {})
        if not miner_config.get("enabled", False):
            return None
        if not miner_config.get("miner_secret_key") or not miner_config.get("target_address"):
            raise ValueError("full_node.xkv8_miner requires miner_secret_key and target_address when enabled")
        return cls(
            config=miner_config,
            coin_store=coin_store,
            add_transaction=add_transaction,
            genesis_challenge=genesis_challenge,
            logger=logger,
        )

    def start(self) -> None:
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = create_referenced_task(self._worker())
            self.log.info(
                "XKV8 miner enabled (aggressive mode). Your mining pubkey: %s target_address=%s",
                bytes(self.builder.pk).hex(),
                self.config.get("target_address"),
            )

    async def stop(self) -> None:
        tasks: list[asyncio.Task[Any]] = []
        if self._worker_task is not None:
            self._worker_task.cancel()
            tasks.append(self._worker_task)
        for task in [*self._build_tasks.values(), *self._nonce_tasks.values()]:
            task.cancel()
            tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def notify_peak(self, event: Xkv8PeakEvent) -> None:
        if self._worker_task is None:
            return
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self._lode_state_dirty = True
        self._queue.put_nowait(event)

    async def _worker(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._handle_peak(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.log.exception("XKV8 miner peak handling failed at height %s", event.height)

    async def _handle_peak(self, event: Xkv8PeakEvent) -> None:
        if event.height <= GENESIS_HEIGHT:
            return

        if event.fork_height < event.height - 1:
            self._lode_state_dirty = True

        if event.is_transaction_block:
            if self._cached_unspent_crs is not None and not self._lode_state_dirty:
                self._apply_block_diff(event)
            else:
                self._lode_state_dirty = True

        if self._cached_unspent_crs is None or self._lode_state_dirty:
            records = await self.coin_store.get_coin_records_by_puzzle_hash(
                False,
                self.builder.full_cat_puzzlehash,
                uint32(0),
                uint32((2**32) - 1),
            )
            self._cached_unspent_crs = {cr.coin.name(): cr for cr in records}
            self._lode_state_dirty = False

        if len(self._cached_unspent_crs) == 0:
            return

        best_cr = max(self._cached_unspent_crs.values(), key=lambda cr: cr.confirmed_block_index)
        self._cached_unspent_crs = {best_cr.coin.name(): best_cr}

        coin_id = best_cr.coin.name()
        new_lode_coin = self._last_lode_cr is None or coin_id != self._last_lode_cr.coin.name()
        if new_lode_coin:
            self._purge_for_new_lode(coin_id)
            self.log.info(
                "XKV8 new lode coin: coin_id=%s confirmed_height=%s peak_height=%s",
                coin_id.hex(),
                best_cr.confirmed_block_index,
                event.height,
            )

        if not await self._ensure_lineage(best_cr):
            return
        self._last_lode_cr = best_cr

        self._drop_stale_targets(int(event.height))
        first_target = max(int(best_cr.confirmed_block_index) + 1, int(event.height) + 1)
        last_target = int(event.height) + self.target_depth
        for target_height in range(first_target, last_target + 1):
            self._start_build_and_submit(best_cr, target_height)

    def _apply_block_diff(self, event: Xkv8PeakEvent) -> None:
        assert self._cached_unspent_crs is not None
        for coin_id, puzzle_hash in event.removals:
            if puzzle_hash == self.builder.full_cat_puzzlehash:
                self._cached_unspent_crs.pop(coin_id, None)

        for coin, _hint in event.additions:
            if coin.puzzle_hash == self.builder.full_cat_puzzlehash:
                self._cached_unspent_crs[coin.name()] = CoinRecord(
                    coin,
                    event.height,
                    uint32(0),
                    False,
                    uint64(0),
                )

    async def _ensure_lineage(self, cr: CoinRecord) -> bool:
        if self.builder._advance_lineage(cr):
            return True

        parent_cr = await self.coin_store.get_coin_record(cr.coin.parent_coin_info)
        if parent_cr is None:
            self.log.warning("XKV8 lineage unavailable: parent coin %s not found", cr.coin.parent_coin_info.hex())
            return False

        lineage = LineageProof(
            parent_cr.coin.parent_coin_info,
            self.builder.inner_puzzle_hash,
            uint64(parent_cr.coin.amount),
        )
        self.builder.set_lineage(cr, lineage)
        return True

    def _purge_for_new_lode(self, coin_id: bytes32) -> None:
        for key, task in list(self._build_tasks.items()):
            if key[0] != coin_id:
                task.cancel()
                self._build_tasks.pop(key, None)
        self._bundles = {key: bundle for key, bundle in self._bundles.items() if key[0] == coin_id}
        self._submitted = {key for key in self._submitted if key[0] == coin_id}

    def _drop_stale_targets(self, peak_height: int) -> None:
        cutoff = peak_height + 1
        for key in [key for key in self._bundles if key[1] < cutoff]:
            self._bundles.pop(key, None)
        for key, task in list(self._build_tasks.items()):
            if key[1] < cutoff:
                task.cancel()
                self._build_tasks.pop(key, None)
        for target in [height for height in self._nonce_cache if height < cutoff]:
            self._nonce_cache.pop(target, None)
        for target, task in list(self._nonce_tasks.items()):
            if target < cutoff:
                task.cancel()
                self._nonce_tasks.pop(target, None)

    def _start_build_and_submit(self, cr: CoinRecord, target_height: int) -> None:
        coin_id = cr.coin.name()
        key = (coin_id, target_height)
        if key in self._submitted or key in self._bundles:
            return
        running = self._build_tasks.get(key)
        if running is not None and not running.done():
            return
        task = create_referenced_task(self._build_and_submit(cr, target_height))
        self._build_tasks[key] = task
        task.add_done_callback(partial(self._finalize_build_task, key))

    def _finalize_build_task(self, key: tuple[bytes32, int], task: asyncio.Task[None]) -> None:
        if self._build_tasks.get(key) is task:
            self._build_tasks.pop(key, None)
        if task.cancelled():
            return
        try:
            task.result()
        except Exception:
            self.log.exception("XKV8 build/submit failed for coin_id=%s target_height=%s", key[0].hex(), key[1])

    async def _build_and_submit(self, cr: CoinRecord, target_height: int) -> None:
        key = (cr.coin.name(), target_height)
        start = time.monotonic()
        nonce = await self._get_nonce(target_height)
        if nonce is None:
            self.log.warning("XKV8 nonce search failed: target_height=%s", target_height)
            return
        bundle = self.builder.build(cr, target_height, nonce)
        self._bundles[key] = CachedBundle(target_height, cr.coin.name(), bundle)
        status, error = await self.add_transaction(bundle, bundle.name())
        if status in {MempoolInclusionStatus.SUCCESS, MempoolInclusionStatus.PENDING}:
            self._submitted.add(key)
        elapsed_ms = (time.monotonic() - start) * 1000
        self.log.info(
            "XKV8 submitted bundle: target_height=%s status=%s error=%s elapsed_ms=%.0f tx=%s",
            target_height,
            status.name,
            None if error is None else error.name,
            elapsed_ms,
            bundle.name().hex(),
        )

    async def _get_nonce(self, target_height: int) -> int | None:
        cached = self._nonce_cache.pop(target_height, None)
        if cached is not None:
            return cached
        task = self._nonce_tasks.get(target_height)
        if task is None:
            task = create_referenced_task(self._compute_nonce(target_height))
            self._nonce_tasks[target_height] = task
        try:
            return await task
        finally:
            if self._nonce_tasks.get(target_height) is task:
                self._nonce_tasks.pop(target_height, None)

    async def _compute_nonce(self, target_height: int) -> int | None:
        difficulty = get_difficulty(get_epoch(target_height))
        async with self._nonce_semaphore:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None,
                partial(
                    find_valid_nonce,
                    self.builder.inner_puzzle_hash,
                    self.builder.pk_bytes,
                    target_height,
                    difficulty,
                ),
            )
