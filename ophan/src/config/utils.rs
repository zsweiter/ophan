pub fn get_parallel_size() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
