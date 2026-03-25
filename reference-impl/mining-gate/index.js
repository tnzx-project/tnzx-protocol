/**
 * Mining Gate — PoW-Based Access Control (Reference Implementation)
 *
 * Binds communication bandwidth to active proof-of-work.
 * Miners must prove ongoing work to unlock VS protocol features.
 *
 * State machine: INACTIVE → GRACE → ACTIVE ↔ SUSPENDED
 *
 * Dependencies: Node.js crypto module only
 *
 * @version 1.0.0
 * @license LGPL-2.1
 */
'use strict';

const crypto = require('crypto');

const ACCESS_LEVEL = {
  INACTIVE: 'inactive',
  GRACE: 'grace',
  ACTIVE: 'active',
  SUSPENDED: 'suspended'
};

const DEFAULT_CONFIG = Object.freeze({
  windowMs: 10 * 60 * 1000,       // 10-minute sliding window
  threshold: 0.5,                   // 50% of expected share rate
  gracePeriodMs: 2 * 60 * 1000,    // 2-minute grace for new miners
  cooldownMs: 5 * 60 * 1000,       // 5-minute suspension cooldown
  minSharesActivation: 3,           // Shares needed to exit GRACE
  checkIntervalMs: null,            // Random 60-180s (set per check)
  minHashrate: 10                   // Minimum H/s to count as active
});

/**
 * Individual miner state tracker
 */
class MinerState {
  constructor(address) {
    this.address = address;
    this.id = crypto.createHash('sha256').update(address).digest('hex').slice(0, 16);

    this.state = ACCESS_LEVEL.INACTIVE;
    this.recentShares = [];          // { timestamp, difficulty }
    this.totalShares = 0;
    this.connectedAt = null;
    this.suspendedAt = null;
  }

  /**
   * Record a valid share submission
   * @param {number} difficulty - Share difficulty
   */
  recordShare(difficulty) {
    const now = Date.now();
    this.totalShares++;
    this.recentShares.push({ timestamp: now, difficulty });

    if (this.state === ACCESS_LEVEL.INACTIVE) {
      this.state = ACCESS_LEVEL.GRACE;
      this.connectedAt = now;
    }
  }

  /**
   * Calculate hashrate from sliding window
   * @param {number} windowMs - Window size
   * @returns {number} Estimated H/s
   *
   * NOTE: This is a pure getter — does NOT mutate recentShares.
   * Use pruneShares() explicitly for cleanup.
   */
  getHashrate(windowMs) {
    const cutoff = Date.now() - windowMs;
    const windowShares = this.recentShares.filter(s => s.timestamp > cutoff);

    if (windowShares.length === 0) return 0;
    const totalDiff = windowShares.reduce((sum, s) => sum + s.difficulty, 0);
    // Use actual elapsed time between first and last share, not full window size,
    // to avoid underestimating hashrate for miners who recently started.
    const first = windowShares[0].timestamp;
    const last = windowShares[windowShares.length - 1].timestamp;
    const elapsedMs = Math.max(last - first, 1000); // Minimum 1 second to avoid division by near-zero
    return Math.floor(totalDiff / (elapsedMs / 1000));
  }

  /**
   * Remove shares older than the given window.
   * Call this explicitly during periodic checks, not inside getters.
   * @param {number} windowMs
   */
  pruneShares(windowMs) {
    const cutoff = Date.now() - windowMs;
    this.recentShares = this.recentShares.filter(s => s.timestamp > cutoff);
  }

  /**
   * Get number of shares in current window
   * @param {number} windowMs
   * @returns {number}
   */
  getShareCount(windowMs) {
    const cutoff = Date.now() - windowMs;
    return this.recentShares.filter(s => s.timestamp > cutoff).length;
  }
}

/**
 * Mining Gate controller
 *
 * Manages access control for all connected miners based on
 * their proof-of-work activity.
 */
class MiningGate {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.miners = new Map();   // address → MinerState
    this.checkTimer = null;
  }

  /**
   * Start periodic verification checks
   */
  start() {
    this._scheduleCheck();
    return this;
  }

  /**
   * Stop verification
   */
  stop() {
    if (this.checkTimer) {
      clearTimeout(this.checkTimer);
      this.checkTimer = null;
    }
  }

  /**
   * Record a valid share from a miner
   * @param {string} address - Wallet address
   * @param {number} difficulty - Share difficulty
   * @returns {{ state: string, shareCount: number }}
   */
  recordShare(address, difficulty) {
    const miner = this._getMiner(address);
    miner.recordShare(difficulty);

    // Check activation from GRACE
    if (miner.state === ACCESS_LEVEL.GRACE) {
      const count = miner.getShareCount(this.config.gracePeriodMs);
      if (count >= this.config.minSharesActivation) {
        miner.state = ACCESS_LEVEL.ACTIVE;
      }
    }

    // Check reactivation from SUSPENDED
    if (miner.state === ACCESS_LEVEL.SUSPENDED) {
      const now = Date.now();
      if (miner.suspendedAt && (now - miner.suspendedAt) >= this.config.cooldownMs) {
        const hashrate = miner.getHashrate(this.config.windowMs);
        if (hashrate >= this.config.minHashrate) {
          miner.state = ACCESS_LEVEL.ACTIVE;
          miner.suspendedAt = null;
        }
      }
    }

    return {
      state: miner.state,
      shareCount: miner.getShareCount(this.config.windowMs)
    };
  }

  /**
   * Check if miner has access (channel is OPEN)
   * @param {string} address
   * @returns {boolean}
   */
  isOpen(address) {
    const miner = this.miners.get(address);
    return miner ? miner.state === ACCESS_LEVEL.ACTIVE : false;
  }

  /**
   * Get miner's current state
   * @param {string} address
   * @returns {string} ACCESS_LEVEL value
   */
  getState(address) {
    const miner = this.miners.get(address);
    return miner ? miner.state : ACCESS_LEVEL.INACTIVE;
  }

  /**
   * Get full status for a miner
   * @param {string} address
   * @returns {Object}
   */
  getStatus(address) {
    const miner = this._getMiner(address);
    const hashrate = miner.getHashrate(this.config.windowMs);
    const shareCount = miner.getShareCount(this.config.windowMs);

    return {
      address: miner.address.slice(0, 12) + '...',
      state: miner.state,
      channelOpen: miner.state === ACCESS_LEVEL.ACTIVE,
      hashrate,
      sharesInWindow: shareCount,
      totalShares: miner.totalShares,
      config: {
        windowMs: this.config.windowMs,
        threshold: this.config.threshold,
        minHashrate: this.config.minHashrate
      }
    };
  }

  /**
   * Get aggregate stats
   */
  getStats() {
    let active = 0, grace = 0, suspended = 0;
    for (const m of this.miners.values()) {
      if (m.state === ACCESS_LEVEL.ACTIVE) active++;
      else if (m.state === ACCESS_LEVEL.GRACE) grace++;
      else if (m.state === ACCESS_LEVEL.SUSPENDED) suspended++;
    }
    return { total: this.miners.size, active, grace, suspended };
  }

  // --- Internal ---

  _getMiner(address) {
    if (!this.miners.has(address)) {
      this.miners.set(address, new MinerState(address));
    }
    return this.miners.get(address);
  }

  /**
   * Periodic check — verify all miners meet threshold
   * Check interval is RANDOM (60-180s) to prevent gaming
   */
  _scheduleCheck() {
    const interval = 60000 + crypto.randomInt(0, 120001); // 60-180 seconds

    this.checkTimer = setTimeout(() => {
      this._checkAllMiners();
      this._scheduleCheck(); // Schedule next (random interval)
    }, interval);
  }

  _checkAllMiners() {
    for (const miner of this.miners.values()) {
      // Prune old shares during periodic check (not in getters)
      miner.pruneShares(this.config.windowMs);

      if (miner.state !== ACCESS_LEVEL.ACTIVE) continue;

      const hashrate = miner.getHashrate(this.config.windowMs);

      if (hashrate < this.config.minHashrate) {
        miner.state = ACCESS_LEVEL.SUSPENDED;
        miner.suspendedAt = Date.now();
      }
    }
  }

  /**
   * Remove stale miners (no activity for 2x window)
   */
  cleanup() {
    const cutoff = Date.now() - (this.config.windowMs * 2);
    for (const [addr, miner] of this.miners) {
      if (miner.recentShares.length === 0 ||
          miner.recentShares[miner.recentShares.length - 1].timestamp < cutoff) {
        this.miners.delete(addr);
      }
    }
  }
}

module.exports = {
  MiningGate,
  MinerState,
  ACCESS_LEVEL,
  DEFAULT_CONFIG
};
