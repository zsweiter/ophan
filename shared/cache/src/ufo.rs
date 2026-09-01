use futures::future::{FutureExt, Shared};
use pingora_memory_cache::CacheStatus as PingoraCacheStatus;
use pingora_memory_cache::MemoryCache as PingoraMemoryCache;
use std::{
    borrow::Borrow,
    collections::{HashMap, hash_map::DefaultHasher},
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

/// Number of shards used by default for the single-flight in-flight table.
const DEFAULT_SHARDS: usize = 16;

/// Type-erased error used by [`MemoryCache::get_or_fetch`] so the in-flight
/// table doesn't need a per-call error generic.
pub type BoxError = Arc<dyn std::error::Error + Send + Sync>;

type BoxedFuture<T> = Pin<Box<dyn Future<Output = Result<T, BoxError>> + Send>>;
type InFlightFetch<T> = Shared<BoxedFuture<T>>;

#[derive(Debug, PartialEq, Eq)]
/// [CacheStatus] indicates the response type for a query.
pub enum CacheStatus {
    /// The key was found in the cache
    Hit,
    /// The key was not found.
    Miss,
    /// The key was found but it was expired.
    Expired,
    /// The key was not initially found but was found after awaiting a lock.
    LockHit,
    /// The returned value was expired but still returned. The [Duration] is
    /// how long it has been since its expiration time.
    Stale(Duration),
}

impl CacheStatus {
    /// Return the string representation for [CacheStatus].
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Expired => "expired",
            Self::LockHit => "lock_hit",
            Self::Stale(_) => "stale",
        }
    }

    /// Returns whether this status represents a cache hit.
    pub fn is_hit(&self) -> bool {
        match self {
            CacheStatus::Hit | CacheStatus::LockHit | CacheStatus::Stale(_) => true,
            CacheStatus::Miss | CacheStatus::Expired => false,
        }
    }

    /// Returns the stale duration if any
    pub fn stale(&self) -> Option<Duration> {
        match self {
            CacheStatus::Stale(time) => Some(*time),
            _ => None,
        }
    }
}

impl From<PingoraCacheStatus> for CacheStatus {
    fn from(status: PingoraCacheStatus) -> Self {
        match status {
            PingoraCacheStatus::Hit => Self::Hit,
            PingoraCacheStatus::Miss => Self::Miss,
            PingoraCacheStatus::Expired => Self::Expired,
            PingoraCacheStatus::LockHit => Self::LockHit,
            PingoraCacheStatus::Stale(duration) => Self::Stale(duration),
        }
    }
}

/// A high performant in-memory cache with S3-FIFO + TinyLFU
pub struct MemoryCache<K: Hash, T: Clone> {
    inner: PingoraMemoryCache<K, T>,
    /// Sharded table of in-flight fetches, used by [`MemoryCache::get_or_fetch`]
    /// to implement single-flight request coalescing. Each shard has its own
    /// lock so concurrent misses on different keys don't contend on a single
    /// global mutex.
    inflight: Vec<AsyncMutex<HashMap<K, InFlightFetch<T>>>>,
}

impl<K: Hash, T: Clone + Send + Sync + 'static> MemoryCache<K, T> {
    /// Create a new [MemoryCache] with the given size, using the default
    /// number of shards for single-flight coalescing.
    pub fn new(size: usize) -> Self {
        Self::new_with_shards(size, DEFAULT_SHARDS)
    }

    /// Create a new [MemoryCache] with the given size and an explicit number
    /// of shards for the single-flight in-flight table. Use more shards if
    /// you expect many keys to miss concurrently and want to minimize lock
    /// contention between unrelated keys; a single shard degrades to one
    /// global lock.
    pub fn new_with_shards(size: usize, shards: usize) -> Self {
        let shards = shards.max(1);
        MemoryCache {
            inner: PingoraMemoryCache::new(size),
            inflight: (0..shards).map(|_| AsyncMutex::new(HashMap::new())).collect(),
        }
    }

    /// Fetch the key and return its value in addition to a [CacheStatus].
    #[inline]
    pub fn get<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, status) = self.inner.get(key);
        (value, status.into())
    }

    /// Fetch the key and return only its value as an [Option].
    #[inline]
    pub fn get_value<Q>(&self, key: &Q) -> Option<T>
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, _) = self.get(key);
        value
    }

    /// Similar to [Self::get], fetch the key and return its value in addition to a
    /// [CacheStatus] but also return the value even if it is expired. When the
    /// value is expired, the [Duration] of how long it has been stale will
    /// also be returned.
    #[inline]
    pub fn get_stale<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let (value, status) = self.inner.get_stale(key);
        (value, status.into())
    }

    /// Insert a key and value pair with an optional TTL into the cache.
    ///
    /// An item with zero TTL of zero will not be inserted.
    #[inline]
    pub fn put<Q>(&self, key: &Q, value: T, ttl: Option<Duration>)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        if let Some(t) = ttl
            && t.is_zero()
        {
            return;
        }

        self.inner.put(key, value, ttl);
    }

    /// Remove a key from the cache if it exists.
    #[inline]
    pub fn remove<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        self.inner.remove(key);
    }

    /// This is equivalent to [MemoryCache::get] but for an arbitrary amount of keys.
    #[inline]
    pub fn multi_get<'a, I, Q>(&self, keys: I) -> Vec<(Option<T>, CacheStatus)>
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        for key in keys {
            resp.push(self.get(key));
        }
        resp
    }

    /// Same as [MemoryCache::multi_get] but returns the keys that are missing from the cache.
    #[inline]
    pub fn multi_get_with_miss<'a, I, Q>(&self, keys: I) -> (Vec<(Option<T>, CacheStatus)>, Vec<&'a Q>)
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        let mut missed = Vec::with_capacity(keys.size_hint().0 / 2);
        for key in keys {
            let (lookup, cache_status) = self.get(key);
            if lookup.is_none() {
                missed.push(key);
            }
            resp.push((lookup, cache_status));
        }
        (resp, missed)
    }

    /// Pick which shard of the in-flight table a key belongs to.
    fn shard_for<Q>(&self, key: &Q) -> usize
    where
        Q: Hash + ?Sized,
    {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.inflight.len()
    }

    /// Fetch `key` from the cache, or -- on a miss -- run `fetch` to compute
    /// it, store the result with `ttl`, and return it.
    ///
    /// This implements **single-flight** request coalescing: if several
    /// callers concurrently request the same missing key, only the first one
    /// (the "leader") actually runs `fetch`. Every other caller (a
    /// "follower") awaits that same in-flight future instead of running its
    /// own `fetch`, so a cache miss never causes duplicate work against your
    /// origin/database for the same key.
    ///
    /// The in-flight table is **sharded** (see [`Self::new_with_shards`]):
    /// each key only ever touches the lock of its own shard, so misses on
    /// unrelated keys never block each other. Only callers racing on the
    /// *same* key (thus the same shard) briefly contend, and only for the
    /// time it takes to check/insert/remove one map entry -- not for the
    /// duration of the fetch itself.
    ///
    /// Errors from `fetch` are type-erased into [`BoxError`] so the in-flight
    /// table doesn't need a per-call error type parameter; a failed fetch is
    /// never written to the cache, and the key is freed up so a later call
    /// can retry it.
    pub async fn get_or_fetch<F, Fut, E>(&self, key: K, ttl: Option<Duration>, fetch: F) -> Result<T, BoxError>
    where
        K: Eq + Clone,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        // Fast path: already cached, no locking needed at all.
        if let Some(value) = self.get_value(&key) {
            return Ok(value);
        }

        let shard_idx = self.shard_for(&key);

        // Either join an existing in-flight fetch, or become the leader that
        // registers a new one. The shard lock is only held for this quick
        // check-and-insert, not while the fetch itself runs.
        let (shared, is_leader) = {
            let mut shard = self.inflight[shard_idx].lock().await;
            if let Some(existing) = shard.get(&key) {
                (existing.clone(), false)
            } else {
                let boxed: BoxedFuture<T> = Box::pin(async move { fetch().await.map_err(|e| Arc::new(e) as BoxError) });
                let shared = boxed.shared();
                shard.insert(key.clone(), shared.clone());
                (shared, true)
            }
        };

        let result = shared.await;

        if is_leader {
            // Free the slot so future misses on this key can retry, and
            // populate the cache on success.
            self.inflight[shard_idx].lock().await.remove(&key);
            if let Ok(ref value) = result {
                self.put(&key, value.clone(), ttl);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn cache_status_as_str() {
        assert_eq!(CacheStatus::Hit.as_str(), "hit");
        assert_eq!(CacheStatus::Miss.as_str(), "miss");
        assert_eq!(CacheStatus::Expired.as_str(), "expired");
        assert_eq!(CacheStatus::LockHit.as_str(), "lock_hit");
        assert_eq!(CacheStatus::Stale(Duration::from_secs(5)).as_str(), "stale");
    }

    #[test]
    fn cache_status_is_hit() {
        assert!(CacheStatus::Hit.is_hit());
        assert!(CacheStatus::LockHit.is_hit());
        assert!(CacheStatus::Stale(Duration::from_secs(1)).is_hit());
        assert!(!CacheStatus::Miss.is_hit());
        assert!(!CacheStatus::Expired.is_hit());
    }

    #[test]
    fn cache_status_stale_returns_duration() {
        let d = Duration::from_secs(42);
        assert_eq!(CacheStatus::Stale(d).stale(), Some(d));
        assert_eq!(CacheStatus::Hit.stale(), None);
        assert_eq!(CacheStatus::Miss.stale(), None);
        assert_eq!(CacheStatus::Expired.stale(), None);
        assert_eq!(CacheStatus::LockHit.stale(), None);
    }

    #[test]
    fn cache_status_from_pingora() {
        assert_eq!(CacheStatus::from(PingoraCacheStatus::Hit), CacheStatus::Hit);
        assert_eq!(CacheStatus::from(PingoraCacheStatus::Miss), CacheStatus::Miss);
        assert_eq!(CacheStatus::from(PingoraCacheStatus::Expired), CacheStatus::Expired);
        assert_eq!(CacheStatus::from(PingoraCacheStatus::LockHit), CacheStatus::LockHit);
        let d = Duration::from_secs(3);
        assert_eq!(CacheStatus::from(PingoraCacheStatus::Stale(d)), CacheStatus::Stale(d));
    }

    #[test]
    fn memory_cache_put_and_get() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"key", "value", Some(Duration::from_secs(60)));
        let (val, status) = c.get(&"key");
        assert_eq!(val, Some("value"));
        assert_eq!(status, CacheStatus::Hit);
    }

    #[test]
    fn memory_cache_get_miss() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        let (val, status) = c.get(&"missing");
        assert_eq!(val, None);
        assert_eq!(status, CacheStatus::Miss);
    }

    #[test]
    fn memory_cache_get_value() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_secs(60)));
        assert_eq!(c.get_value(&"k"), Some("v"));
        assert_eq!(c.get_value(&"missing"), None);
    }

    #[test]
    fn memory_cache_put_zero_ttl_not_inserted() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::ZERO));
        assert_eq!(c.get_value(&"k"), None);
    }

    #[test]
    fn memory_cache_remove() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_secs(60)));
        c.remove(&"k");
        assert_eq!(c.get_value(&"k"), None);
    }

    #[test]
    fn memory_cache_multi_get() {
        let c: MemoryCache<&str, i32> = MemoryCache::new(100);
        c.put(&"a", 1, Some(Duration::from_secs(60)));
        c.put(&"b", 2, Some(Duration::from_secs(60)));
        let results = c.multi_get(["a", "b", "c"].iter());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], (Some(1), CacheStatus::Hit));
        assert_eq!(results[1], (Some(2), CacheStatus::Hit));
        assert_eq!(results[2].0, None);
    }

    #[test]
    fn memory_cache_multi_get_with_miss() {
        let c: MemoryCache<&str, i32> = MemoryCache::new(100);
        c.put(&"a", 1, Some(Duration::from_secs(60)));
        let (results, missed) = c.multi_get_with_miss(["a", "b", "c"].iter());
        assert_eq!(results.len(), 3);
        assert_eq!(missed, vec![&"b", &"c"]);
    }

    #[test]
    fn memory_cache_get_stale_returns_expired_value() {
        let c: MemoryCache<&str, &str> = MemoryCache::new(100);
        c.put(&"k", "v", Some(Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(30));
        let (val, status) = c.get_stale(&"k");
        assert_eq!(val, Some("v"));
        assert!(matches!(status, CacheStatus::Stale(_)));
    }

    #[tokio::test]
    async fn get_or_fetch_dedupes_concurrent_calls() {
        let cache = Arc::new(MemoryCache::<&str, i32>::new(100));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_fetch("k", Some(Duration::from_secs(60)), move || {
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Ok::<i32, std::io::Error>(42)
                        }
                    })
                    .await
            }));
        }

        for h in handles {
            assert_eq!(h.await.unwrap().unwrap(), 42);
        }

        // Only the leader should have actually run the fetch.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_or_fetch_skips_fetch_on_hit() {
        let cache: MemoryCache<&str, i32> = MemoryCache::new(100);
        cache.put(&"k", 7, Some(Duration::from_secs(60)));

        let result = cache
            .get_or_fetch("k", Some(Duration::from_secs(60)), || async {
                panic!("fetch should not run on a cache hit");
                #[allow(unreachable_code)]
                Ok::<i32, std::io::Error>(0)
            })
            .await;

        assert_eq!(result.unwrap(), 7);
    }

    #[tokio::test]
    async fn get_or_fetch_propagates_error_and_does_not_cache() {
        let cache: MemoryCache<&str, i32> = MemoryCache::new(100);

        let result = cache
            .get_or_fetch("k", Some(Duration::from_secs(60)), || async {
                Err::<i32, _>(std::io::Error::new(std::io::ErrorKind::Other, "boom"))
            })
            .await;

        assert!(result.is_err());
        assert_eq!(cache.get_value(&"k"), None);
    }
}
